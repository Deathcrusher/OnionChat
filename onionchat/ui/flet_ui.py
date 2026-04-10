"""
Modern Flet-based UI for OnionChat.

Features:
- Clean, modern design
- Real-time messaging
- QR code display
- File transfer support
- Dark/Light theme
"""

import asyncio
import logging
from typing import Optional, Callable, Awaitable
from datetime import datetime

import flet as ft

from ..core import (
    ChatSession,
    ChatMessage,
    SessionConfig,
    SessionCredentials,
    SessionState,
)
from ..transport import TransportConfig
from ..utils.qr import generate_qr_image

logger = logging.getLogger(__name__)


class ChatUI(ft.UserControl):
    """Main chat UI component."""
    
    def __init__(self, page: ft.Page):
        super().__init__()
        self.page = page
        self.session: Optional[ChatSession] = None
        self.is_host = True
        self._running = False
        
        # UI components
        self.status_text: Optional[ft.Text] = None
        self.chat_display: Optional[ft.Column] = None
        self.message_input: Optional[ft.TextField] = None
        self.send_button: Optional[ft.ElevatedButton] = None
        self.qr_dialog: Optional[ft.AlertDialog] = None
    
    async def _on_message(self, msg: ChatMessage):
        """Handle incoming message."""
        if self.chat_display:
            self.chat_display.controls.append(
                ft.Container(
                    content=ft.Text(f"{msg.sender}: {msg.content}", size=14),
                    padding=8,
                    bgcolor=ft.colors.SURFACE_VARIANT,
                    border_radius=8,
                    margin=ft.margin.only(bottom=4),
                )
            )
            await self.chat_display.update_async()
            await self._scroll_to_bottom()
    
    async def _on_status(self, status: str):
        """Handle status update."""
        if self.status_text:
            self.status_text.value = status
            await self.status_text.update_async()
    
    async def _scroll_to_bottom(self):
        """Scroll chat display to bottom."""
        if self.chat_display:
            await self.page.update_async()
    
    def _add_message(self, text: str, is_self: bool = True):
        """Add a message to the chat display."""
        if not self.chat_display:
            return
        
        align = ft.alignment.center_right if is_self else ft.alignment.center_left
        color = ft.colors.PRIMARY_CONTAINER if is_self else ft.colors.SURFACE_VARIANT
        
        self.chat_display.controls.append(
            ft.Row(
                [
                    ft.Container(
                        content=ft.Text(text, size=14, color=ft.colors.ON_SURFACE),
                        padding=ft.padding.all(10),
                        bgcolor=color,
                        border_radius=ft.border_radius.only(
                            top_left=10,
                            top_right=10,
                            bottom_left=0 if is_self else 10,
                            bottom_right=10 if is_self else 0,
                        ),
                    )
                ],
                alignment=align,
            )
        )
    
    async def _send_message(self, e):
        """Send message button handler."""
        if not self.message_input or not self.session:
            return
        
        text = self.message_input.value.strip()
        if not text:
            return
        
        if text.lower() == "exit":
            await self._stop_session()
            return
        
        try:
            self._add_message(text, is_self=True)
            await self.message_input.update_async()
            
            await self.session.send_message(text)
            self.message_input.value = ""
            await self.message_input.update_async()
            
        except Exception as ex:
            logger.error(f"Failed to send message: {ex}")
            await self._show_error(f"Failed to send: {ex}")
    
    async def _show_error(self, message: str):
        """Show error dialog."""
        dlg = ft.AlertDialog(
            title=ft.Text("Error"),
            content=ft.Text(message),
            actions=[
                ft.TextButton("OK", on_click=lambda e: self.page.close(dlg))
            ],
        )
        self.page.dialog = dlg
        dlg.open = True
        await self.page.update_async()
    
    async def _show_qr_dialog(self, credentials: SessionCredentials):
        """Show QR code dialog for sharing credentials."""
        qr_image = generate_qr_image(credentials.to_qr_data())
        
        dlg = ft.AlertDialog(
            title=ft.Text("Share Session"),
            content=ft.Column(
                [
                    ft.Text("Scan this QR code with Client B:", size=14),
                    ft.Image(src=qr_image, width=250, height=250),
                    ft.Text(f"Session ID: {credentials.session_id[:16]}...", size=12),
                    ft.Text(f"Onion: {credentials.onion_address}", size=12, selectable=True),
                ],
                tight=True,
            ),
            actions=[
                ft.TextButton("Copy Link", on_click=lambda e: self._copy_credentials(credentials)),
                ft.TextButton("Close", on_click=lambda e: self.page.close(dlg)),
            ],
            modal=True,
        )
        
        self.page.dialog = dlg
        dlg.open = True
        await self.page.update_async()
    
    def _copy_credentials(self, credentials: SessionCredentials):
        """Copy credentials to clipboard."""
        self.page.set_clipboard(credentials.to_qr_data())
        ft.Snackbar(content=ft.Text("Copied to clipboard!")).open = True
        self.page.snack_bar.open = True
        self.page.update()
    
    async def _start_host_session(self, e):
        """Start hosting a session."""
        self.is_host = True
        await self._initialize_session()
    
    async def _join_session(self, e):
        """Join an existing session."""
        self.is_host = False
        # Show dialog to enter credentials
        self._show_join_dialog()
    
    def _show_join_dialog(self):
        """Show dialog to join session."""
        qr_input = ft.TextField(
            label="Paste QR Data or Onion Address",
            multiline=True,
            min_lines=3,
            max_lines=5,
        )
        
        dlg = ft.AlertDialog(
            title=ft.Text("Join Session"),
            content=qr_input,
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.page.close(dlg)),
                ft.TextButton("Connect", on_click=lambda e: self._connect_to_session(e, qr_input.value)),
            ],
            modal=True,
        )
        
        self.page.dialog = dlg
        dlg.open = True
        self.page.update()
    
    async def _connect_to_session(self, e, qr_data: str):
        """Connect to existing session."""
        if not qr_data:
            await self._show_error("Please enter session credentials")
            return
        
        try:
            # TODO: Parse QR data and connect
            await self._initialize_session(join_data=qr_data)
        except Exception as ex:
            await self._show_error(f"Failed to connect: {ex}")
    
    async def _initialize_session(self, join_data: Optional[str] = None):
        """Initialize and start chat session."""
        try:
            config = SessionConfig.generate()
            transport_config = TransportConfig(port=config.hidden_service_port)
            
            self.session = ChatSession(
                config=config,
                is_host=self.is_host,
                transport_config=transport_config
            )
            
            self.session.set_message_callback(self._on_message)
            self.session.set_status_callback(self._on_status)
            
            await self._on_status("Initializing...")
            await self.session.initialize()
            
            if self.is_host:
                await self.session.start()
                credentials = self.session.get_credentials()
                await self._show_qr_dialog(credentials)
            else:
                # TODO: Implement join flow
                await self._show_error("Join flow not yet implemented")
            
            self._running = True
            
            if self.send_button:
                self.send_button.disabled = False
                await self.send_button.update_async()
            
            await self._on_status("Connected - Ready to chat!")
            
        except Exception as ex:
            logger.exception("Failed to initialize session")
            await self._show_error(f"Initialization failed: {ex}")
    
    async def _stop_session(self):
        """Stop current session."""
        if self.session:
            await self.session.stop()
            self.session = None
            self._running = False
            
            if self.send_button:
                self.send_button.disabled = True
                await self.send_button.update_async()
            
            await self._on_status("Session terminated")
    
    def _build_header(self):
        """Build app header."""
        return ft.Container(
            content=ft.Row(
                [
                    ft.Icon(ft.icons.ENCRYPTED, color=ft.colors.PRIMARY),
                    ft.Text("OnionChat", size=20, weight=ft.FontWeight.BOLD),
                    ft.VerticalDivider(),
                    self.status_text := ft.Text(
                        "Ready",
                        size=12,
                        color=ft.colors.ON_SURFACE_VARIANT,
                    ),
                ],
                alignment=ft.MainAxisAlignment.START,
            ),
            padding=16,
            bgcolor=ft.colors.SURFACE,
        )
    
    def _build_chat_area(self):
        """Build chat message area."""
        return ft.Container(
            content=self.chat_display := ft.Column(
                scroll=ft.ScrollMode.AUTO,
                spacing=4,
            ),
            expand=True,
            padding=16,
        )
    
    def _build_input_area(self):
        """Build message input area."""
        return ft.Container(
            content=ft.Row(
                [
                    self.message_input := ft.TextField(
                        hint_text="Type a message...",
                        expand=True,
                        on_submit=self._send_message,
                    ),
                    self.send_button := ft.ElevatedButton(
                        "Send",
                        icon=ft.icons.SEND,
                        on_click=self._send_message,
                        disabled=True,
                    ),
                    ft.IconButton(
                        icon=ft.icons.ATTACH_FILE,
                        tooltip="Send file",
                        on_click=lambda e: self._show_file_picker(),
                    ),
                    ft.IconButton(
                        icon=ft.icons.STOP,
                        tooltip="End session",
                        on_click=self._stop_session_handler,
                    ),
                ],
            ),
            padding=16,
            bgcolor=ft.colors.SURFACE,
        )
    
    async def _stop_session_handler(self, e):
        """Handle stop session button click."""
        await self._stop_session()
    
    def _show_file_picker(self):
        """Show file picker dialog."""
        self.page.dialog = ft.FilePicker(on_result=self._handle_file_picked)
        self.page.dialog.pick_files()
        self.page.update()
    
    async def _handle_file_picked(self, e: ft.FilePickerResultEvent):
        """Handle file picker result."""
        if e.files:
            file_path = e.files[0].path
            if file_path:
                # TODO: Implement file transfer
                await self._show_error("File transfer coming soon!")
    
    def build(self):
        """Build the UI component."""
        return ft.Column(
            [
                self._build_header(),
                ft.Divider(height=1),
                self._build_chat_area(),
                ft.Divider(height=1),
                self._build_input_area(),
            ],
            expand=True,
        )


def create_app(page: ft.Page):
    """Create the main app."""
    page.title = "OnionChat - Secure Anonymous Chat"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 0
    page.spacing = 0
    
    # Add logo/header banner
    page.appbar = ft.AppBar(
        leading=ft.Icon(ft_icons.ENCRYPTED, color=ft.colors.WHITE),
        leading_width=40,
        title=ft.Text("OnionChat", font_family="Roboto", size=20),
        center_title=False,
        bgcolor=ft.colors.SURFACE_VARIANT,
        actions=[
            ft.IconButton(ft.icons.QR_CODE, tooltip="Show QR"),
            ft.IconButton(ft.icons.SETTINGS, tooltip="Settings"),
        ],
    )
    
    chat_ui = ChatUI(page)
    
    # Welcome screen with host/join options
    welcome = ft.Container(
        content=ft.Column(
            [
                ft.Icon(ft.icons.ENCRYPTED, size=100, color=ft.colors.PRIMARY),
                ft.Text(
                    "Welcome to OnionChat",
                    size=24,
                    weight=ft.FontWeight.BOLD,
                ),
                ft.Text(
                    "Secure, anonymous, one-time chat via Tor",
                    size=14,
                    color=ft.colors.ON_SURFACE_VARIANT,
                ),
                ft.Divider(height=30),
                ft.Row(
                    [
                        ft.ElevatedButton(
                            "Host Session",
                            icon=ft.icons.ADD,
                            on_click=chat_ui._start_host_session,
                            style=ft.ButtonStyle(
                                padding=20,
                                minimum_size=200,
                            ),
                        ),
                        ft.ElevatedButton(
                            "Join Session",
                            icon=ft.icons.LOGIN,
                            on_click=chat_ui._join_session,
                            style=ft.ButtonStyle(
                                padding=20,
                                minimum_size=200,
                            ),
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    spacing=20,
                ),
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        expand=True,
        alignment=ft.alignment.center,
    )
    
    page.add(welcome, chat_ui)


async def main_async(page: ft.Page):
    """Async main entry point."""
    create_app(page)


def main(page: ft.Page):
    """Main entry point."""
    create_app(page)


# Import fix for flet icons
ft_icons = ft.icons
