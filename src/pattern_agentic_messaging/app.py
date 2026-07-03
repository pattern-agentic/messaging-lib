import asyncio
import logging
from slim_bindings import (
    App,
    CaSource,
    ClientConfig,
    MessageContext,
    Service,
    SessionConfig,
    SessionType,
    TlsClientConfig,
    TlsSource,
    initialize_with_defaults,
    is_initialized,
    uniffi_set_event_loop,
    get_global_service,
    new_tracing_config,
    new_runtime_config,
    new_service_config,
    initialize_with_configs,
)
from typing import AsyncIterator, Optional, Literal, get_type_hints, get_origin, get_args
from .config import PASlimConfig
from .session import PASlimSession, PASlimP2PSession, PASlimGroupSession
from .auth import create_none_auth, create_shared_secret_auth, create_jwt_auth, JWTClaims
from .session_token import PatternAgentSessionToken
from .message_types import PASystemError
from .types import MessagePayload
from .exceptions import AuthenticationError
from .utils import parse_name

logger = logging.getLogger(__name__)

try:
    from pydantic import BaseModel, ValidationError
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    BaseModel = None
    ValidationError = None


def _extract_literal_value(model: type, field_name: str) -> Optional[str]:
    """Extract Literal value from a Pydantic model field."""
    try:
        hints = get_type_hints(model)
        field_type = hints.get(field_name)
        if get_origin(field_type) is Literal:
            args = get_args(field_type)
            if args:
                return args[0]
    except Exception:
        pass
    return None


def _get_pydantic_model_from_handler(func) -> Optional[type]:
    if not PYDANTIC_AVAILABLE:
        return None
    try:
        hints = get_type_hints(func)
        msg_type = hints.get('msg')
        if msg_type and isinstance(msg_type, type) and issubclass(msg_type, BaseModel):
            return msg_type
    except Exception:
        pass
    return None


def _extract_required_keys(model: type) -> frozenset[str]:
    """Extract the wire-level required field names from a Pydantic model.

    Uses the alias (JSON key) when present, falling back to the Python field name.
    Computed once at handler registration time.
    """
    keys = set()
    for name, field in model.model_fields.items():
        if field.is_required():
            keys.add(field.alias if field.alias else name)
    return frozenset(keys)


def _inspect_handler(func) -> dict:
    try:
        hints = get_type_hints(func)
    except Exception:
        return {'wants_ctx': False, 'wants_claims': False, 'claims_param': None, 'session_token_param': None}
    wants_ctx = hints.get('msg_context') is MessageContext
    claims_param = None
    session_token_param = None
    for name, hint in hints.items():
        if hint is JWTClaims:
            claims_param = name
        elif hint is PatternAgentSessionToken:
            session_token_param = name
    return {
        'wants_ctx': wants_ctx,
        'wants_claims': claims_param is not None,
        'claims_param': claims_param,
        'session_token_param': session_token_param,
    }


async def _call_handler(handler, session, msg, msg_ctx, injection, session_token_verifier=None):
    kwargs = {}
    if injection['wants_ctx']:
        kwargs['msg_context'] = msg_ctx
    if injection['wants_claims']:
        kwargs[injection['claims_param']] = JWTClaims.from_token(msg_ctx.identity)
    if injection['session_token_param']:
        try:
            token = PatternAgentSessionToken.from_metadata(msg_ctx.metadata)
        except Exception as e:
            logger.warning(f"Session token extraction failed: {e}")
            await session.send(PASystemError(error="invalid_session_token", detail=str(e)).to_payload())
            return
        if session_token_verifier:
            try:
                await session_token_verifier(token.raw_token)
            except Exception as e:
                logger.warning(f"Session token verification failed: {e}")
                await session.send(PASystemError(error="session_token_verification_failed", detail=str(e)).to_payload())
                return
        kwargs[injection['session_token_param']] = token
    await handler(session, msg, **kwargs)


class PASlimApp:
    def __init__(self, config: PASlimConfig):
        self.config = config
        self._service: Optional[Service] = None
        self._app: Optional[App] = None
        self._conn_id: Optional[int] = None
        self._message_handlers = []
        self._session_connect_handler = None
        self._session_disconnect_handler = None
        self._init_handlers = []
        self._running = True
        self.session_token_verifier = None
        self._audit_publisher = None
        self._client_config = None
        self._maintain_task = None

    async def __aenter__(self):
        auth_type = self.config.auth_type

        if auth_type == "none":
            auth_provider, auth_verifier = create_none_auth()
        elif auth_type == "shared_secret":
            if not self.config.auth_secret:
                raise AuthenticationError("auth_secret is required for shared_secret auth")
            if len(self.config.auth_secret) < 32:
                raise AuthenticationError("auth_secret must be at least 32 bytes")
            auth_provider, auth_verifier = create_shared_secret_auth(
                self.config.local_name,
                self.config.auth_secret,
            )
        elif auth_type == "jwt":
            if not self.config.jwt_token_path:
                raise AuthenticationError("jwt_token_path is required for jwt auth")
            auth_provider, auth_verifier = create_jwt_auth(
                self.config.jwt_token_path,
                jwks_url=self.config.jwt_jwks_url,
                jwks_content=self.config.jwt_jwks_content,
                issuer=self.config.jwt_issuer,
                audience=self.config.jwt_audience,
                subject=self.config.jwt_subject,
                duration=self.config.jwt_token_duration,
            )
        else:
            raise AuthenticationError(f"Unknown auth_type: {auth_type}")

        uniffi_set_event_loop(asyncio.get_running_loop())

        if not is_initialized():
            initialize_with_configs(
                tracing_config=new_tracing_config(),
                runtime_config=new_runtime_config(),
                service_config=[new_service_config()],
            )

        service = get_global_service()
        tls = TlsClientConfig(
            insecure=self.config.tls_insecure,
            insecure_skip_verify=False,
            source=TlsSource.NONE(),
            ca_source=CaSource.NONE(),
            include_system_ca_certs_pool=not self.config.tls_insecure,
            tls_version="tls1.3",
        )
        client_config = ClientConfig(
            endpoint=self.config.endpoint,
            tls=tls,
            headers=self.config.custom_headers,
        )
        self._client_config = client_config
        logger.info(f"SLIM __aenter__: connecting to endpoint={self.config.endpoint}")
        conn_id = await service.connect_async(client_config)
        logger.info(f"SLIM __aenter__: connected conn_id={conn_id}")

        local_name = parse_name(self.config.local_name)
        if auth_type == "shared_secret":
            app = service.create_app_with_secret(local_name, self.config.auth_secret)
        else:
            app = service.create_app(local_name, auth_provider, auth_verifier)
        logger.info(f"SLIM __aenter__: app created name={self.config.local_name}")

        await app.subscribe_async(local_name, conn_id)
        logger.info(f"SLIM __aenter__: subscribed name={self.config.local_name}")

        self._service = service
        self._app = app
        self._conn_id = conn_id

        if self.config.audit_nats_url:
            try:
                from .audit import AuditPublisher
                self._audit_publisher = AuditPublisher(
                    self.config.audit_nats_url,
                    subject_prefix=self.config.audit_nats_subject_prefix,
                    creds_file=self.config.audit_nats_creds_file,
                )
                await self._audit_publisher.connect()
            except Exception as e:
                logger.warning(f"Audit publisher init failed (audit disabled): {e}")
                self._audit_publisher = None

        if self.config.resubscribe_enabled:
            self._maintain_task = asyncio.create_task(self._maintain_subscription())

        return self

    async def _maintain_subscription(self):
        local_name = parse_name(self.config.local_name)
        while True:
            try:
                await asyncio.sleep(self.config.resubscribe_interval_sec)
                await self._app.subscribe_async(local_name, self._conn_id)
                logger.debug("SLIM maintain: re-subscribed inbound route")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"SLIM maintain: re-subscribe failed ({e}); reconnecting")
                try:
                    try:
                        self._service.disconnect(self._conn_id)
                    except Exception:
                        pass
                    conn_id = await self._service.connect_async(self._client_config)
                    await self._app.subscribe_async(local_name, conn_id)
                    self._conn_id = conn_id
                    logger.info(f"SLIM maintain: reconnected + re-subscribed conn_id={conn_id}")
                except Exception as e2:
                    logger.error(f"SLIM maintain: reconnect failed: {e2}")

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._maintain_task:
            self._maintain_task.cancel()
            try:
                await self._maintain_task
            except (asyncio.CancelledError, Exception):
                pass
            self._maintain_task = None

        if self._audit_publisher:
            try:
                await self._audit_publisher.close()
            except Exception:
                pass
            self._audit_publisher = None

        if self._service:
            try:
                self._service.disconnect(self._conn_id)
            except Exception as e:
                if exc_type is not None:
                    logger.debug(f"SLIM disconnect during error cleanup: {e}")
                else:
                    logger.warning(f"SLIM disconnect failed: {e}")
            finally:
                self._app = None
                self._service = None
                self._conn_id = None

    def __aiter__(self):
        return self.messages()

    def on_message(self, discriminator=None, value=None):
        """
        Decorator to register a message handler with optional filtering.

        Can be used as a direct decorator or with discriminator arguments.
        Supports Pydantic model type hints for automatic parsing.

        Examples:
            # Catch-all handler (no filter)
            @app.on_message
            async def handler(session, msg):
                await session.send(response)

            # Filtered by value (requires message_discriminator in config)
            @app.on_message('prompt')
            async def handler(session, msg):
                # Called when msg[config.message_discriminator] == 'prompt'
                await session.send(response)

            # Filtered by explicit field and value (legacy)
            @app.on_message('type', 'prompt')
            async def handler(session, msg):
                # Only called when msg['type'] == 'prompt'
                await session.send(response)

            # Pydantic model handler (requires message_discriminator in config)
            @app.on_message
            async def handler(session, msg: PromptMessage):
                # msg is automatically parsed as PromptMessage
                await session.send(response)
        """
        def _register_handler(func, disc_field, disc_value):
            model = _get_pydantic_model_from_handler(func)
            model_disc_value = None

            if model:
                if self.config.message_discriminator:
                    model_disc_value = _extract_literal_value(
                        model, self.config.message_discriminator
                    )

            self._message_handlers.append({
                'discriminator': disc_field,
                'value': disc_value,
                'handler': func,
                'model': model,
                'discriminator_value': model_disc_value,
                'required_keys': _extract_required_keys(model) if model else None,
                'injection': _inspect_handler(func),
            })
            return func

        # Direct decoration: @app.on_message
        if callable(discriminator):
            func = discriminator
            return _register_handler(func, None, None)

        # Single argument: @app.on_message('prompt') - uses config.message_discriminator
        if discriminator is not None and value is None:
            if not self.config.message_discriminator:
                raise ValueError(
                    f"Single-argument @on_message('{discriminator}') requires "
                    f"config.message_discriminator to be set"
                )
            return lambda func: _register_handler(func, self.config.message_discriminator, discriminator)

        # Two arguments: @app.on_message('type', 'prompt')
        return lambda func: _register_handler(func, discriminator, value)

    def on_session_connect(self, func):
        """
        Decorator to register a session connect handler.

        The handler will be called when a new session is established.

        Example:
            @app.on_session_connect
            async def handler(session):
                logger.info(f"Session {session.session_id} connected")
        """
        self._session_connect_handler = func
        return func

    def on_session_disconnect(self, func):
        """
        Decorator to register a session disconnect handler.

        The handler will be called when a session ends.

        Example:
            @app.on_session_disconnect
            async def handler(session):
                logger.info(f"Session {session.session_id} disconnected")
        """
        self._session_disconnect_handler = func
        return func

    def on_init(self, func):
        """
        Decorator to register an async initialization handler.

        Multiple handlers can be registered; they run in order.
        Called once at app startup, after connection but before message handling.
        If any handler raises an exception, the app will abort with error details.

        Example:
            @app.on_init
            async def init():
                await setup_database()
        """
        self._init_handlers.append(func)
        return func

    def stop(self):
        """Stop the application gracefully."""
        self._running = False

    def run(self):
        """
        Run the application with automatic event loop and signal handling.

        This is a synchronous method that sets up signal handlers,
        creates an event loop, and runs the async message handling loop.

        Signal handling:
        - First SIGINT/SIGTERM: graceful shutdown (waits for cleanup)
        - Second signal: forced shutdown (cancels immediately)

        Example:
            app = PASlimApp(config)

            @app.on_message
            async def handler(session, msg):
                await session.send(response)

            app.run()  # Blocks until stopped
        """
        import signal as sig

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        self._running = True
        main_task = None
        shutdown_requested = False

        def signal_handler():
            nonlocal shutdown_requested
            if not shutdown_requested:
                shutdown_requested = True
                self.stop()
            elif main_task and not main_task.done():
                main_task.cancel()

        for s in (sig.SIGTERM, sig.SIGINT):
            loop.add_signal_handler(s, signal_handler)

        try:
            main_task = loop.create_task(self._run_async())
            loop.run_until_complete(main_task)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            for s in (sig.SIGTERM, sig.SIGINT):
                loop.remove_signal_handler(s)
            loop.close()

    async def _run_async(self):
        """Internal async runner for the decorator pattern."""
        if not self._message_handlers:
            raise ValueError("No message handlers registered. Use @app.on_message decorator.")

        # Find catch-all handler (no discriminator, no model)
        catch_all_info = None
        for handler_info in self._message_handlers:
            if (handler_info['discriminator'] is None
                    and handler_info.get('discriminator_value') is None
                    and handler_info.get('model') is None):
                catch_all_info = handler_info
                break

        disc_field = self.config.message_discriminator

        async with self:
            for init_handler in self._init_handlers:
                try:
                    await init_handler()
                except Exception as e:
                    logger.error(f"App initialization failed: {e}", exc_info=True)
                    return

            async for session, msg_ctx, msg in self:
                if not self._running:
                    break

                matched = False
                for handler_info in self._message_handlers:
                    disc = handler_info['discriminator']
                    val = handler_info['value']
                    handler = handler_info['handler']
                    model = handler_info.get('model')
                    model_disc_val = handler_info.get('discriminator_value')
                    required_keys = handler_info.get('required_keys')
                    injection = handler_info['injection']

                    if model and isinstance(msg, dict):
                        # Discriminator-matched model handler
                        if model_disc_val is not None:
                            if msg.get(disc_field) != model_disc_val:
                                continue
                            try:
                                parsed = model.model_validate(msg)
                                matched = True
                                try:
                                    await _call_handler(handler, session, parsed, msg_ctx, injection, self.session_token_verifier)
                                except Exception as exc:
                                    logger.error(f"Error in handler '{handler.__name__}' for message type '{model.__name__}': {exc}", exc_info=True)
                                break
                            except ValidationError as e:
                                matched = True
                                await session.send({
                                    "error": "validation_error",
                                    "details": e.errors()
                                })
                                break

                        # Model-only handler: structural pre-check then try-validate
                        elif required_keys is not None:
                            if not required_keys <= msg.keys():
                                continue
                            try:
                                parsed = model.model_validate(msg)
                                matched = True
                                try:
                                    await _call_handler(handler, session, parsed, msg_ctx, injection, self.session_token_verifier)
                                except Exception as exc:
                                    logger.error(f"Error in handler '{handler.__name__}' for message type '{model.__name__}': {exc}", exc_info=True)
                                break
                            except ValidationError:
                                continue

                    # Legacy dict-based handler
                    elif disc is not None:
                        if isinstance(msg, dict) and msg.get(disc) == val:
                            matched = True
                            try:
                                await _call_handler(handler, session, msg, msg_ctx, injection, self.session_token_verifier)
                            except Exception as exc:
                                logger.error(f"Error in handler '{handler.__name__}' for discriminator {disc}={val}: {exc}", exc_info=True)
                            break

                # Fall back to catch-all if no specific handler matched
                if not matched and catch_all_info:
                    handler = catch_all_info['handler']
                    model = catch_all_info.get('model')
                    injection = catch_all_info['injection']
                    try:
                        if model and isinstance(msg, dict):
                            parsed = model.model_validate(msg)
                            await _call_handler(handler, session, parsed, msg_ctx, injection, self.session_token_verifier)
                        else:
                            await _call_handler(handler, session, msg, msg_ctx, injection, self.session_token_verifier)
                    except ValidationError as e:
                        await session.send({
                            "error": "validation_error",
                            "details": e.errors()
                        })
                    except Exception as exc:
                        logger.error(f"Error in fallback message handler '{handler.__name__}': {exc}", exc_info=True)
                elif not matched:
                    logger.warning(f"No handler for message: {msg}")

    def _session_config(self, session_type: SessionType) -> SessionConfig:
        return SessionConfig(
            session_type=session_type,
            enable_mls=self.config.mls_enabled,
            max_retries=self.config.max_retries,
            interval=self.config.timeout,
            metadata={},
        )

    async def connect(self, peer_name: str, timeout: Optional[float] = None) -> PASlimP2PSession:
        """
        Connect to a peer (P2P Active mode).

        Args:
            peer_name: Peer identifier (e.g., "org/namespace/app")
            timeout: Connection timeout in seconds (default: config.connect_timeout_sec)

        Returns:
            PASlimP2PSession for communicating with the peer

        Raises:
            asyncio.TimeoutError: If the peer doesn't respond within the timeout
        """
        connect_timeout = timeout or self.config.connect_timeout_sec
        peer = parse_name(peer_name)
        await self._app.set_route_async(peer, self._conn_id)
        session = await asyncio.wait_for(
            self._app.create_session_and_wait_async(
                self._session_config(SessionType.POINT_TO_POINT), peer
            ),
            timeout=connect_timeout,
        )
        return PASlimP2PSession(session, audit_publisher=self._audit_publisher, local_name=self.config.local_name, peer_name=peer_name)

    async def accept(self) -> PASlimP2PSession:
        """
        Accept a single incoming P2P session (P2P Passive mode).

        Returns:
            PASlimP2PSession for the incoming connection
        """
        session = await self._app.listen_for_session_async(None)
        return PASlimP2PSession(session, audit_publisher=self._audit_publisher, local_name=self.config.local_name)

    async def create_channel(self, channel_name: str, invites: list[str] = None) -> PASlimGroupSession:
        """
        Create a group channel and invite participants (Group Moderator mode).

        Args:
            channel_name: Channel identifier (e.g., "org/namespace/channel")
            invites: List of participant names to invite

        Returns:
            PASlimGroupSession for the channel
        """
        if invites is None:
            invites = []

        channel = parse_name(channel_name)
        slim_session = await self._app.create_session_and_wait_async(
            self._session_config(SessionType.GROUP), channel
        )
        session = PASlimGroupSession(slim_session, audit_publisher=self._audit_publisher, local_name=self.config.local_name, peer_name=channel_name)

        for invite in invites:
            participant = parse_name(invite)
            await self._app.set_route_async(participant, self._conn_id)
            await session.invite(invite)

        return session

    async def join_channel(self) -> PASlimGroupSession:
        """
        Join a group channel by accepting an invite (Group Participant mode).

        Returns:
            PASlimGroupSession for the channel
        """
        session = await self._app.listen_for_session_async(None)
        return PASlimGroupSession(session, audit_publisher=self._audit_publisher, local_name=self.config.local_name)

    async def listen(self) -> AsyncIterator[PASlimP2PSession]:
        """
        Listen for incoming P2P sessions (P2P Passive mode).

        Yields:
            PASlimP2PSession for each incoming connection
        """
        while True:
            session = await self._app.listen_for_session_async(None)
            yield PASlimP2PSession(session, audit_publisher=self._audit_publisher, local_name=self.config.local_name)

    async def messages(self) -> AsyncIterator[tuple[PASlimSession, MessageContext, MessagePayload]]:
        """
        Iterate over messages from all incoming sessions.

        Yields (session, message) tuples from all active sessions.
        Automatically manages session lifecycle - listens for new sessions,
        starts their message loops, and multiplexes messages into a single stream.

        Designed for servers handling multiple concurrent clients.

        Example:
            async with PASlimApp(config) as app:
                async for session, msg in app:
                    await session.send(response)
        """
        message_queue: asyncio.Queue = asyncio.Queue()
        session_tasks: set[asyncio.Task] = set()
        listener_task: Optional[asyncio.Task] = None

        async def session_reader(session: PASlimSession):
            """Read messages from a session and forward to queue."""
            try:
                # Call session connect handler if registered
                if self._session_connect_handler:
                    try:
                        await self._session_connect_handler(session)
                    except Exception as e:
                        logger.error(f"Error in session connect handler: {e}", exc_info=True)

                async with session:
                    while True:
                        try:
                            msg_ctx, msg = await session._next_with_context()
                        except StopAsyncIteration:
                            break
                        await message_queue.put((session, msg_ctx, msg))
            except (StopAsyncIteration, asyncio.CancelledError):
                pass
            except Exception as e:
                logger.error(f"Session reader error: {e}", exc_info=True)
            finally:
                # Call session disconnect handler if registered
                if self._session_disconnect_handler:
                    try:
                        await self._session_disconnect_handler(session)
                    except Exception as e:
                        logger.error(f"Error in session disconnect handler: {e}", exc_info=True)

        async def session_listener():
            """Listen for new sessions and spawn reader tasks."""
            async for session in self.listen():
                task = asyncio.create_task(session_reader(session))
                session_tasks.add(task)
                task.add_done_callback(session_tasks.discard)

        try:
            listener_task = asyncio.create_task(session_listener())

            while self._running:
                # Check if listener crashed
                if listener_task.done():
                    exc = listener_task.exception()
                    if exc:
                        raise exc
                    break  # Listener ended (shouldn't happen)

                # Get next message with timeout to periodically check listener health
                try:
                    session, msg_ctx, msg = await asyncio.wait_for(
                        message_queue.get(),
                        timeout=0.1
                    )
                    yield (session, msg_ctx, msg)
                except asyncio.TimeoutError:
                    continue  # No message yet, loop back

        finally:
            # Cleanup: cancel all tasks with timeout to avoid hanging
            if listener_task and not listener_task.done():
                listener_task.cancel()
                try:
                    await asyncio.wait_for(listener_task, timeout=0.5)
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    pass

            for task in list(session_tasks):
                task.cancel()

            if session_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*session_tasks, return_exceptions=True),
                        timeout=0.5
                    )
                except asyncio.TimeoutError:
                    pass
