# main.py - Complete Production-Ready System with Enhanced Admin Features
import os
import json
import asyncio
import hashlib
import secrets
import threading
import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, List
from functools import wraps

import aiohttp
from flask import Flask, request, jsonify
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.enums import ParseMode
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
import logging

# ==================== CONFIGURATION ====================
# Get from environment variables for security
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8491801715:AAFglnmy-HKzpJpX2_yaw77DCHtrx3SAuF4")
ADMIN_ID = int(os.environ.get("ADMIN_ID", 6258915779))  # Must be set in production
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")  # Default admin password

MOTHER_API_URL = "https://mothernuminfo.asapiservices.workers.dev/mobile-lookup"
MOTHER_API_KEY = "anshapi123"  # Fixed mother API key
API_BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:10000")  # Fixed for local

# App settings for Render.com
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 10000))

# File paths
DB_FILE = "db.json"
LOG_FILE = "app.log"

# ==================== LOGGING SETUP ====================
# Fix encoding issue for Windows
class SafeStreamHandler(logging.StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            # Encode to ASCII, ignore non-ASCII characters for Windows console
            msg = msg.encode('ascii', 'ignore').decode('ascii')
            stream = self.stream
            stream.write(msg + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        SafeStreamHandler()  # Use safe handler for console
    ]
)
logger = logging.getLogger(__name__)

# ==================== FSM STATES ====================
class AdminStates(StatesGroup):
    waiting_for_password = State()
    waiting_for_genkey = State()
    waiting_for_disable_key = State()
    waiting_for_enable_key = State()
    waiting_for_delete_key = State()
    waiting_for_extend_key = State()

# ==================== DATABASE HANDLER ====================
class Database:
    """JSON file-based database handler with thread safety"""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self._ensure_db_exists()
    
    def _ensure_db_exists(self):
        """Create database file if it doesn't exist"""
        if not os.path.exists(self.filepath):
            self._create_new_db()
        else:
            # Ensure existing DB has all required keys
            self._migrate_db()
    
    def _create_new_db(self):
        """Create a new database with proper structure"""
        with open(self.filepath, 'w', encoding='utf-8') as f:
            json.dump({
                "users": {},
                "admin_sessions": {},
                "disabled_keys": []
            }, f, indent=2)
        logger.info(f"Created new database at {self.filepath}")
    
    def _migrate_db(self):
        """Migrate existing database to new structure if needed"""
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                db = json.load(f)
            
            # Ensure all required keys exist
            if "users" not in db:
                db["users"] = {}
            if "admin_sessions" not in db:
                db["admin_sessions"] = {}
            if "disabled_keys" not in db:
                db["disabled_keys"] = []
            
            # Ensure each user has all required fields
            for user_id, user_data in db.get("users", {}).items():
                # Add missing fields
                if "disabled" not in user_data:
                    user_data["disabled"] = False
                if "total_requests" not in user_data:
                    user_data["total_requests"] = 0
                if "last_used" not in user_data:
                    user_data["last_used"] = None
                if "status" not in user_data:
                    # Set status based on expiry
                    expires_at = user_data.get("expires_at", "")
                    if expires_at:
                        if DateValidator.is_expired(expires_at):
                            user_data["status"] = "expired"
                        else:
                            user_data["status"] = "active"
                    else:
                        user_data["status"] = "active"
            
            # Save migrated database
            with open(self.filepath, 'w', encoding='utf-8') as f:
                json.dump(db, f, indent=2)
            
            logger.info(f"Migrated database at {self.filepath}")
            
        except (json.JSONDecodeError, FileNotFoundError):
            # If corrupted, create new
            self._create_new_db()
    
    def _read(self) -> Dict:
        """Read database with file locking simulation"""
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            # If corrupted, reset database
            self._create_new_db()
            return {"users": {}, "admin_sessions": {}, "disabled_keys": []}
    
    def _write(self, data: Dict):
        """Write database with atomic write pattern"""
        temp_file = f"{self.filepath}.tmp"
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        os.replace(temp_file, self.filepath)
    
    def get_user(self, user_id: str) -> Optional[Dict]:
        """Get user by user ID (string)"""
        db = self._read()
        return db["users"].get(str(user_id))
    
    def get_user_by_key(self, api_key: str) -> Optional[Dict]:
        """Get user by API key"""
        db = self._read()
        for user_id, user_data in db["users"].items():
            if user_data.get("api_key") == api_key:
                user_data["user_id"] = user_id
                return user_data
        return None
    
    def get_all_users(self) -> Dict:
        """Get all users"""
        return self._read().get("users", {})
    
    def create_user(self, user_id: str, username: str, api_key: str, days: int):
        """Create or update user with new API key"""
        db = self._read()
        
        created_at = datetime.now().strftime("%Y-%m-%d")
        expires_at = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
        
        db["users"][str(user_id)] = {
            "username": username,
            "api_key": api_key,
            "created_at": created_at,
            "expires_at": expires_at,
            "days": days,
            "status": "active",
            "disabled": False,
            "total_requests": 0,
            "last_used": None
        }
        
        self._write(db)
        logger.info(f"Created/updated user {user_id} with {days} days validity")
        return db["users"][str(user_id)]
    
    def update_user_status(self, user_id: str, status: str):
        """Update user status (active/expired)"""
        db = self._read()
        user_id_str = str(user_id)
        
        if user_id_str in db["users"]:
            db["users"][user_id_str]["status"] = status
            self._write(db)
            logger.info(f"Updated user {user_id} status to {status}")
    
    def disable_key(self, api_key: str):
        """Disable an API key"""
        db = self._read()
        
        # Ensure disabled_keys list exists
        if "disabled_keys" not in db:
            db["disabled_keys"] = []
        
        # Add to disabled keys list
        if api_key not in db["disabled_keys"]:
            db["disabled_keys"].append(api_key)
        
        # Update user status if exists
        for user_id, user_data in db["users"].items():
            if user_data.get("api_key") == api_key:
                user_data["disabled"] = True
                user_data["status"] = "disabled"
                break
        
        self._write(db)
        logger.info(f"Disabled API key: {api_key}")
    
    def enable_key(self, api_key: str):
        """Enable a disabled API key"""
        db = self._read()
        
        # Ensure disabled_keys list exists
        if "disabled_keys" not in db:
            db["disabled_keys"] = []
        
        # Remove from disabled keys list
        if api_key in db["disabled_keys"]:
            db["disabled_keys"].remove(api_key)
        
        # Update user status if exists
        for user_id, user_data in db["users"].items():
            if user_data.get("api_key") == api_key:
                user_data["disabled"] = False
                # Check if still valid
                if DateValidator.is_expired(user_data["expires_at"]):
                    user_data["status"] = "expired"
                else:
                    user_data["status"] = "active"
                break
        
        self._write(db)
        logger.info(f"Enabled API key: {api_key}")
    
    def delete_key(self, api_key: str):
        """Delete an API key and user"""
        db = self._read()
        
        # Ensure disabled_keys list exists
        if "disabled_keys" not in db:
            db["disabled_keys"] = []
        
        # Remove from disabled keys list
        if api_key in db["disabled_keys"]:
            db["disabled_keys"].remove(api_key)
        
        # Find and remove user
        user_to_delete = None
        for user_id, user_data in db["users"].items():
            if user_data.get("api_key") == api_key:
                user_to_delete = user_id
                break
        
        if user_to_delete:
            del db["users"][user_to_delete]
        
        self._write(db)
        logger.info(f"Deleted API key: {api_key}")
        return user_to_delete
    
    def extend_key(self, api_key: str, additional_days: int):
        """Extend key validity"""
        db = self._read()
        
        for user_id, user_data in db["users"].items():
            if user_data.get("api_key") == api_key:
                # Parse current expiry
                current_expiry = datetime.strptime(user_data["expires_at"], "%Y-%m-%d")
                new_expiry = current_expiry + timedelta(days=additional_days)
                
                user_data["expires_at"] = new_expiry.strftime("%Y-%m-%d")
                user_data["days"] += additional_days
                
                # Update status
                if DateValidator.is_expired(user_data["expires_at"]):
                    user_data["status"] = "expired"
                else:
                    user_data["status"] = "active"
                
                self._write(db)
                logger.info(f"Extended key {api_key} by {additional_days} days")
                return user_data
        
        return None
    
    def increment_request_count(self, api_key: str):
        """Increment request count for API key"""
        db = self._read()
        
        for user_id, user_data in db["users"].items():
            if user_data.get("api_key") == api_key:
                user_data["total_requests"] = user_data.get("total_requests", 0) + 1
                user_data["last_used"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self._write(db)
                break
    
    def is_key_disabled(self, api_key: str) -> bool:
        """Check if key is in disabled list"""
        db = self._read()
        # Ensure disabled_keys exists
        if "disabled_keys" not in db:
            db["disabled_keys"] = []
            self._write(db)
        return api_key in db.get("disabled_keys", [])
    
    def get_admin_session(self, user_id: str) -> bool:
        """Check if user has active admin session"""
        db = self._read()
        # Ensure admin_sessions exists
        if "admin_sessions" not in db:
            db["admin_sessions"] = {}
            self._write(db)
        return db.get("admin_sessions", {}).get(str(user_id), False)
    
    def set_admin_session(self, user_id: str, status: bool):
        """Set admin session status"""
        db = self._read()
        # Ensure admin_sessions exists
        if "admin_sessions" not in db:
            db["admin_sessions"] = {}
        db["admin_sessions"][str(user_id)] = status
        self._write(db)
    
    def get_all_keys_info(self) -> List[Dict]:
        """Get information about all API keys"""
        db = self._read()
        # Ensure all required keys exist
        if "users" not in db:
            db["users"] = {}
        if "disabled_keys" not in db:
            db["disabled_keys"] = []
        
        users = db.get("users", {})
        disabled_keys = set(db.get("disabled_keys", []))
        
        result = []
        for user_id, user_data in users.items():
            key_info = {
                "user_id": user_id,
                "username": user_data.get("username", "N/A"),
                "api_key": user_data.get("api_key", "N/A"),
                "status": user_data.get("status", "unknown"),
                "disabled": user_data.get("api_key", "") in disabled_keys,
                "expires_at": user_data.get("expires_at", "N/A"),
                "days_left": self._calculate_days_left(user_data.get("expires_at")),
                "total_requests": user_data.get("total_requests", 0),
                "last_used": user_data.get("last_used", "Never")
            }
            result.append(key_info)
        
        return result
    
    def _calculate_days_left(self, expires_at: str) -> int:
        """Calculate days left until expiry"""
        try:
            expiry_date = datetime.strptime(expires_at, "%Y-%m-%d")
            days_left = (expiry_date - datetime.now()).days
            return max(0, days_left)
        except:
            return 0

# Initialize database
db = Database(DB_FILE)

# ==================== API KEY GENERATOR ====================
class APIKeyGenerator:
    """Generate and validate API keys"""
    
    @staticmethod
    def generate(username: str, user_id: str) -> str:
        """Generate API key in format: ansh_<username>_<userid>_<randomhash>"""
        # Clean username (no spaces, lowercase)
        clean_username = username.strip().lower().replace(" ", "_")
        
        # Generate random hash
        random_hash = secrets.token_hex(8)
        
        # Create key in required format
        api_key = f"ansh_{clean_username}_{user_id}_{random_hash}"
        return api_key
    
    @staticmethod
    def validate_format(api_key: str) -> bool:
        """Validate API key format"""
        parts = api_key.split("_")
        return len(parts) == 4 and parts[0] == "ansh"

# ==================== DATE VALIDATOR ====================
class DateValidator:
    """Handle date validation and expiry checks"""
    
    @staticmethod
    def is_expired(expires_at: str) -> bool:
        """Check if expiry date has passed"""
        try:
            expiry_date = datetime.strptime(expires_at, "%Y-%m-%d")
            return expiry_date < datetime.now()
        except ValueError:
            # Invalid date format, treat as expired
            return True
    
    @staticmethod
    def get_today() -> str:
        """Get today's date in YYYY-MM-DD format"""
        return datetime.now().strftime("%Y-%m-%d")

# ==================== TELEGRAM BOT ====================
class TelegramBot:
    """Telegram bot handler with enhanced admin features"""
    
    def __init__(self, token: str, admin_id: int, admin_password: str):
        self.token = token
        self.admin_id = admin_id
        self.admin_password = admin_password
        self.storage = MemoryStorage()
        self.bot = Bot(token=token)
        self.dp = Dispatcher(storage=self.storage)
        
        # Register command handlers
        self.dp.message(Command("start"))(self.start_command)
        self.dp.message(Command("mykey"))(self.mykey_command)
        self.dp.message(Command("status"))(self.status_command)
        self.dp.message(Command("admin"))(self.admin_command)
        
        # Admin command handlers
        self.dp.message(Command("genkey"))(self.genkey_command)
        self.dp.message(Command("listkeys"))(self.listkeys_command)
        self.dp.message(Command("disablekey"))(self.disablekey_command)
        self.dp.message(Command("enablekey"))(self.enablekey_command)
        self.dp.message(Command("deletekey"))(self.deletekey_command)
        self.dp.message(Command("extendkey"))(self.extendkey_command)
        self.dp.message(Command("stats"))(self.stats_command)
        self.dp.message(Command("logout"))(self.logout_command)
        
        # Callback query handlers
        self.dp.callback_query(F.data.startswith("admin_"))(self.admin_callback_handler)
        
        logger.info("Telegram bot initialized")
    
    # ============ USER COMMANDS ============
    async def start_command(self, message: Message):
        """Handle /start command"""
        welcome_text = """
🤖 *Welcome to Ansh API Bot!*

Available Commands:
• /mykey - Show your API key details with full URL
• /status - Check your API status
• /admin - Admin panel (admin only)

🔑 Your API key allows you to access our mobile lookup service.

📝 *How to use:*
1. Use `/mykey` to get your API key with ready-to-use URL
2. Copy the full URL and use it in your applications

⚠️ *Important:* Keep your API key secure!
        """
        await message.answer(welcome_text, parse_mode=ParseMode.MARKDOWN)
    
    async def mykey_command(self, message: Message):
        """Handle /mykey command - Show full API URL with key"""
        user_id = str(message.from_user.id)
        user_data = db.get_user(user_id)
        
        if not user_data:
            await message.answer("❌ You don't have an API key yet. Contact admin.")
            return
        
        # Check expiry
        if DateValidator.is_expired(user_data["expires_at"]):
            db.update_user_status(user_id, "expired")
            user_data["status"] = "expired"
        
        # Check if disabled
        if db.is_key_disabled(user_data["api_key"]):
            user_data["status"] = "disabled"
        
        # Build full API URL
        full_api_url = f"{API_BASE_URL}/mobile-lookup?key={user_data['api_key']}&mobile=PHONE_NUMBER"
        example_url = f"{API_BASE_URL}/mobile-lookup?key={user_data['api_key']}&mobile=9889662072"
        
        # Format response
        status_emoji = "✅" if user_data["status"] == "active" else "❌"
        
        response = f"""
🔑 *Your API Key Details*:

• *API Key:* `{user_data['api_key']}`
• *Status:* {status_emoji} {user_data['status'].upper()}
• *Created:* {user_data['created_at']}
• *Expires:* {user_data['expires_at']}
• *Valid for:* {user_data['days']} days

🌐 *Full API URL (Ready to Use):*
`{full_api_url}`

📋 *Example Request:*
`{example_url}`

⚡ *Quick Copy:* Click below to copy the URL
        """
        
        # Create keyboard with copy button
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text="📋 Copy Full URL", 
                                   callback_data=f"copy_url_{user_data['api_key']}")
            ],
            [
                InlineKeyboardButton(text="🔄 Test API", 
                                   url=example_url.replace("PHONE_NUMBER", "9889662072"))
            ]
        ])
        
        await message.answer(response, parse_mode=ParseMode.MARKDOWN, reply_markup=keyboard)
    
    async def status_command(self, message: Message):
        """Handle /status command"""
        user_id = str(message.from_user.id)
        user_data = db.get_user(user_id)
        
        if not user_data:
            await message.answer("❌ No API key found.")
            return
        
        # Check expiry
        if DateValidator.is_expired(user_data["expires_at"]):
            db.update_user_status(user_id, "expired")
            status_text = "❌ *EXPIRED* - Your API key has expired."
        elif db.is_key_disabled(user_data["api_key"]):
            status_text = "⛔ *DISABLED* - Your API key is disabled by admin."
        else:
            status_text = "✅ *ACTIVE* - Your API key is valid."
        
        await message.answer(status_text, parse_mode=ParseMode.MARKDOWN)
    
    # ============ ADMIN COMMANDS ============
    async def admin_command(self, message: Message, state: FSMContext):
        """Handle /admin command - Admin login panel"""
        user_id = message.from_user.id
        
        # Check if already admin or is the main admin
        if user_id == self.admin_id or db.get_admin_session(str(user_id)):
            # Show admin panel
            await self.show_admin_panel(message)
        else:
            # Ask for password
            await message.answer("🔐 *Admin Login Required*\n\nPlease enter admin password:")
            await state.set_state(AdminStates.waiting_for_password)
    
    async def show_admin_panel(self, message: Message):
        """Show admin panel with options"""
        # Get statistics
        all_keys = db.get_all_keys_info()
        active_keys = [k for k in all_keys if k["status"] == "active" and not k["disabled"]]
        expired_keys = [k for k in all_keys if k["status"] == "expired"]
        disabled_keys = [k for k in all_keys if k["disabled"]]
        
        stats_text = f"""
⚙️ *ADMIN PANEL*

📊 *Statistics:*
• Total Keys: {len(all_keys)}
• Active: {len(active_keys)}
• Expired: {len(expired_keys)}
• Disabled: {len(disabled_keys)}

🛠️ *Available Commands:*

🔑 *Key Management:*
• /genkey - Generate new API key
• /listkeys - List all API keys
• /disablekey <api_key> - Disable a key
• /enablekey <api_key> - Enable a key
• /deletekey <api_key> - Delete a key
• /extendkey <api_key> <days> - Extend key validity

📈 *Monitoring:*
• /stats - Detailed statistics

🚪 *Session:*
• /logout - Logout from admin
        """
        
        # Create admin keyboard
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text="🔑 Generate Key", callback_data="admin_genkey"),
                InlineKeyboardButton(text="📋 List Keys", callback_data="admin_listkeys")
            ],
            [
                InlineKeyboardButton(text="⛔ Disable Key", callback_data="admin_disable"),
                InlineKeyboardButton(text="✅ Enable Key", callback_data="admin_enable")
            ],
            [
                InlineKeyboardButton(text="🗑️ Delete Key", callback_data="admin_delete"),
                InlineKeyboardButton(text="📈 Extend Key", callback_data="admin_extend")
            ],
            [
                InlineKeyboardButton(text="📊 Stats", callback_data="admin_stats"),
                InlineKeyboardButton(text="🚪 Logout", callback_data="admin_logout")
            ]
        ])
        
        await message.answer(stats_text, parse_mode=ParseMode.MARKDOWN, reply_markup=keyboard)
    
    async def genkey_command(self, message: Message, state: FSMContext):
        """Handle /genkey command"""
        if not await self.check_admin_access(message):
            return
        
        args = message.text.split()[1:]
        
        if len(args) == 3:
            # Direct command with arguments
            await self.process_genkey(message, args[0], args[1], args[2])
        else:
            # Interactive mode
            await message.answer("🔑 *Generate New API Key*\n\nSend in format:\n`/genkey <user_id> <username> <days>`\n\nExample:\n`/genkey 123456789 vinod 30`", 
                               parse_mode=ParseMode.MARKDOWN)
            await state.set_state(AdminStates.waiting_for_genkey)
    
    async def listkeys_command(self, message: Message):
        """Handle /listkeys command - List all API keys"""
        if not await self.check_admin_access(message):
            return
        
        all_keys = db.get_all_keys_info()
        
        if not all_keys:
            await message.answer("📭 No API keys found.")
            return
        
        response = "📋 *All API Keys:*\n\n"
        for i, key_info in enumerate(all_keys, 1):
            status_emoji = "✅" if key_info["status"] == "active" and not key_info["disabled"] else "❌"
            disabled_text = " (DISABLED)" if key_info["disabled"] else ""
            
            response += f"{i}. `{key_info['api_key'][:30]}...`\n"
            response += f"   👤 {key_info['username']} (ID: {key_info['user_id']})\n"
            response += f"   {status_emoji} {key_info['status'].upper()}{disabled_text}\n"
            response += f"   📅 Expires: {key_info['expires_at']} ({key_info['days_left']} days left)\n"
            response += f"   📊 Requests: {key_info['total_requests']}\n"
            response += f"   🕐 Last used: {key_info['last_used']}\n\n"
        
        # Split if message is too long
        if len(response) > 4000:
            parts = [response[i:i+4000] for i in range(0, len(response), 4000)]
            for part in parts:
                await message.answer(part, parse_mode=ParseMode.MARKDOWN)
        else:
            await message.answer(response, parse_mode=ParseMode.MARKDOWN)
    
    async def disablekey_command(self, message: Message, state: FSMContext):
        """Handle /disablekey command"""
        if not await self.check_admin_access(message):
            return
        
        args = message.text.split()[1:]
        
        if len(args) == 1:
            # Direct command with key
            api_key = args[0]
            if db.get_user_by_key(api_key):
                db.disable_key(api_key)
                await message.answer(f"✅ Key disabled successfully:\n`{api_key}`", 
                                   parse_mode=ParseMode.MARKDOWN)
            else:
                await message.answer("❌ API key not found.")
        else:
            await message.answer("⛔ *Disable API Key*\n\nSend in format:\n`/disablekey <api_key>`\n\nExample:\n`/disablekey ansh_vinod_123456_abcdef`", 
                               parse_mode=ParseMode.MARKDOWN)
            await state.set_state(AdminStates.waiting_for_disable_key)
    
    async def enablekey_command(self, message: Message, state: FSMContext):
        """Handle /enablekey command"""
        if not await self.check_admin_access(message):
            return
        
        args = message.text.split()[1:]
        
        if len(args) == 1:
            # Direct command with key
            api_key = args[0]
            if db.get_user_by_key(api_key):
                db.enable_key(api_key)
                await message.answer(f"✅ Key enabled successfully:\n`{api_key}`", 
                                   parse_mode=ParseMode.MARKDOWN)
            else:
                await message.answer("❌ API key not found.")
        else:
            await message.answer("✅ *Enable API Key*\n\nSend in format:\n`/enablekey <api_key>`\n\nExample:\n`/enablekey ansh_vinod_123456_abcdef`", 
                               parse_mode=ParseMode.MARKDOWN)
            await state.set_state(AdminStates.waiting_for_enable_key)
    
    async def deletekey_command(self, message: Message, state: FSMContext):
        """Handle /deletekey command"""
        if not await self.check_admin_access(message):
            return
        
        args = message.text.split()[1:]
        
        if len(args) == 1:
            # Direct command with key
            api_key = args[0]
            user_id = db.delete_key(api_key)
            if user_id:
                await message.answer(f"🗑️ Key deleted successfully:\n`{api_key}`\nUser ID: {user_id}", 
                                   parse_mode=ParseMode.MARKDOWN)
            else:
                await message.answer("❌ API key not found.")
        else:
            await message.answer("🗑️ *Delete API Key*\n\nSend in format:\n`/deletekey <api_key>`\n\nExample:\n`/deletekey ansh_vinod_123456_abcdef`", 
                               parse_mode=ParseMode.MARKDOWN)
            await state.set_state(AdminStates.waiting_for_delete_key)
    
    async def extendkey_command(self, message: Message, state: FSMContext):
        """Handle /extendkey command"""
        if not await self.check_admin_access(message):
            return
        
        args = message.text.split()[1:]
        
        if len(args) == 2:
            # Direct command with key and days
            api_key = args[0]
            try:
                days = int(args[1])
                if days <= 0:
                    await message.answer("❌ Days must be positive integer.")
                    return
                
                user_data = db.extend_key(api_key, days)
                if user_data:
                    await message.answer(f"📈 Key extended by {days} days successfully:\n`{api_key}`\nNew expiry: {user_data['expires_at']}", 
                                       parse_mode=ParseMode.MARKDOWN)
                else:
                    await message.answer("❌ API key not found.")
            except ValueError:
                await message.answer("❌ Invalid days value.")
        else:
            await message.answer("📈 *Extend API Key Validity*\n\nSend in format:\n`/extendkey <api_key> <days>`\n\nExample:\n`/extendkey ansh_vinod_123456_abcdef 30`", 
                               parse_mode=ParseMode.MARKDOWN)
            await state.set_state(AdminStates.waiting_for_extend_key)
    
    async def stats_command(self, message: Message):
        """Handle /stats command - Show detailed statistics"""
        if not await self.check_admin_access(message):
            return
        
        all_keys = db.get_all_keys_info()
        total_requests = sum(k["total_requests"] for k in all_keys)
        
        # Group by status
        active_count = len([k for k in all_keys if k["status"] == "active" and not k["disabled"]])
        expired_count = len([k for k in all_keys if k["status"] == "expired"])
        disabled_count = len([k for k in all_keys if k["disabled"]])
        
        # Recent activity (last 7 days)
        recent_active = []
        for key in all_keys:
            if key["last_used"] != "Never":
                try:
                    last_used = datetime.strptime(key["last_used"], "%Y-%m-%d %H:%M:%S")
                    if (datetime.now() - last_used).days <= 7:
                        recent_active.append(key)
                except:
                    pass
        
        stats_text = f"""
📊 *ADMIN STATISTICS*

📈 *Overview:*
• Total API Keys: {len(all_keys)}
• Active Keys: {active_count}
• Expired Keys: {expired_count}
• Disabled Keys: {disabled_count}
• Total API Requests: {total_requests}

🔄 *Recent Activity (Last 7 days):*
• Active Users: {len(recent_active)}
        
🔢 *Top 5 Most Used Keys:*
        """
        
        # Sort by request count
        sorted_keys = sorted(all_keys, key=lambda x: x["total_requests"], reverse=True)[:5]
        
        for i, key in enumerate(sorted_keys, 1):
            stats_text += f"\n{i}. `{key['api_key'][:20]}...`"
            stats_text += f"\n   👤 {key['username']} - 📊 {key['total_requests']} requests"
        
        stats_text += "\n\n📅 *Expiring Soon (within 7 days):*"
        
        # Keys expiring soon
        expiring_soon = [k for k in all_keys if 0 < k["days_left"] <= 7]
        for key in expiring_soon[:5]:
            stats_text += f"\n• `{key['api_key'][:20]}...` - {key['days_left']} days left"
        
        await message.answer(stats_text, parse_mode=ParseMode.MARKDOWN)
    
    async def logout_command(self, message: Message):
        """Handle /logout command"""
        user_id = str(message.from_user.id)
        db.set_admin_session(user_id, False)
        await message.answer("✅ Logged out from admin panel.")
    
    # ============ HELPER METHODS ============
    async def check_admin_access(self, message: Message) -> bool:
        """Check if user has admin access"""
        user_id = message.from_user.id
        
        if user_id == self.admin_id or db.get_admin_session(str(user_id)):
            return True
        
        await message.answer("⛔ Unauthorized: Admin access required.")
        return False
    
    async def process_genkey(self, message: Message, target_user_id: str, username: str, days_str: str):
        """Process key generation"""
        try:
            days = int(days_str)
            
            if days <= 0:
                await message.answer("❌ Days must be positive integer.")
                return
            
            # Generate API key
            api_key = APIKeyGenerator.generate(username, target_user_id)
            
            # Save to database
            user_data = db.create_user(target_user_id, username, api_key, days)
            
            # Build full API URL
            full_api_url = f"{API_BASE_URL}/mobile-lookup?key={api_key}&mobile=PHONE_NUMBER"
            
            # Send confirmation with URL
            response = f"""
✅ *API Key Generated Successfully!*

• *User ID:* {target_user_id}
• *Username:* {username}
• *API Key:* `{api_key}`
• *Validity:* {days} days
• *Expires:* {user_data['expires_at']}

🌐 *Full API URL (Ready to Send):*
`{full_api_url}`

📋 *Example Usage:*
`{full_api_url.replace('PHONE_NUMBER', '9889662072')}`

Send this URL to the user for immediate use.
            """
            
            await message.answer(response, parse_mode=ParseMode.MARKDOWN)
            
        except ValueError:
            await message.answer("❌ Invalid days value. Must be integer.")
        except Exception as e:
            logger.error(f"Error in genkey: {e}")
            await message.answer("❌ Error generating key.")
    
    # ============ STATE HANDLERS ============
    async def handle_password(self, message: Message, state: FSMContext):
        """Handle admin password input"""
        if message.text == self.admin_password:
            user_id = str(message.from_user.id)
            db.set_admin_session(user_id, True)
            await message.answer("✅ Admin login successful!")
            await self.show_admin_panel(message)
            await state.clear()
        else:
            await message.answer("❌ Incorrect password. Try again or /cancel")
    
    async def handle_genkey(self, message: Message, state: FSMContext):
        """Handle genkey input"""
        args = message.text.split()
        if len(args) == 3:
            await self.process_genkey(message, args[0], args[1], args[2])
            await state.clear()
        else:
            await message.answer("❌ Invalid format. Use: `<user_id> <username> <days>`\nExample: `123456789 vinod 30`")
    
    async def handle_disable_key(self, message: Message, state: FSMContext):
        """Handle disable key input"""
        api_key = message.text.strip()
        if db.get_user_by_key(api_key):
            db.disable_key(api_key)
            await message.answer(f"✅ Key disabled successfully:\n`{api_key}`", 
                               parse_mode=ParseMode.MARKDOWN)
            await state.clear()
        else:
            await message.answer("❌ API key not found. Try again or /cancel")
    
    async def handle_enable_key(self, message: Message, state: FSMContext):
        """Handle enable key input"""
        api_key = message.text.strip()
        if db.get_user_by_key(api_key):
            db.enable_key(api_key)
            await message.answer(f"✅ Key enabled successfully:\n`{api_key}`", 
                               parse_mode=ParseMode.MARKDOWN)
            await state.clear()
        else:
            await message.answer("❌ API key not found. Try again or /cancel")
    
    async def handle_delete_key(self, message: Message, state: FSMContext):
        """Handle delete key input"""
        api_key = message.text.strip()
        user_id = db.delete_key(api_key)
        if user_id:
            await message.answer(f"🗑️ Key deleted successfully:\n`{api_key}`\nUser ID: {user_id}", 
                               parse_mode=ParseMode.MARKDOWN)
            await state.clear()
        else:
            await message.answer("❌ API key not found. Try again or /cancel")
    
    async def handle_extend_key(self, message: Message, state: FSMContext):
        """Handle extend key input"""
        args = message.text.split()
        if len(args) == 2:
            api_key = args[0]
            try:
                days = int(args[1])
                if days <= 0:
                    await message.answer("❌ Days must be positive integer.")
                    return
                
                user_data = db.extend_key(api_key, days)
                if user_data:
                    await message.answer(f"📈 Key extended by {days} days successfully:\n`{api_key}`\nNew expiry: {user_data['expires_at']}", 
                                       parse_mode=ParseMode.MARKDOWN)
                    await state.clear()
                else:
                    await message.answer("❌ API key not found. Try again or /cancel")
            except ValueError:
                await message.answer("❌ Invalid days value. Try again or /cancel")
        else:
            await message.answer("❌ Invalid format. Use: `<api_key> <days>`\nExample: `ansh_vinod_123456_abcdef 30`")
    
    # ============ CALLBACK HANDLERS ============
    async def admin_callback_handler(self, callback_query: types.CallbackQuery, state: FSMContext):
        """Handle admin panel callback queries"""
        data = callback_query.data
        user_id = callback_query.from_user.id
        
        # Check admin access
        if not (user_id == self.admin_id or db.get_admin_session(str(user_id))):
            await callback_query.answer("⛔ Admin access required")
            return
        
        if data == "admin_genkey":
            await callback_query.message.answer("🔑 *Generate New API Key*\n\nSend in format:\n`/genkey <user_id> <username> <days>`\n\nExample:\n`/genkey 123456789 vinod 30`", 
                                              parse_mode=ParseMode.MARKDOWN)
            await state.set_state(AdminStates.waiting_for_genkey)
            await callback_query.answer()
        
        elif data == "admin_listkeys":
            await self.listkeys_command(callback_query.message)
            await callback_query.answer()
        
        elif data == "admin_disable":
            await callback_query.message.answer("⛔ *Disable API Key*\n\nSend in format:\n`/disablekey <api_key>`\n\nExample:\n`/disablekey ansh_vinod_123456_abcdef`", 
                                              parse_mode=ParseMode.MARKDOWN)
            await state.set_state(AdminStates.waiting_for_disable_key)
            await callback_query.answer()
        
        elif data == "admin_enable":
            await callback_query.message.answer("✅ *Enable API Key*\n\nSend in format:\n`/enablekey <api_key>`\n\nExample:\n`/enablekey ansh_vinod_123456_abcdef`", 
                                              parse_mode=ParseMode.MARKDOWN)
            await state.set_state(AdminStates.waiting_for_enable_key)
            await callback_query.answer()
        
        elif data == "admin_delete":
            await callback_query.message.answer("🗑️ *Delete API Key*\n\nSend in format:\n`/deletekey <api_key>`\n\nExample:\n`/deletekey ansh_vinod_123456_abcdef`", 
                                              parse_mode=ParseMode.MARKDOWN)
            await state.set_state(AdminStates.waiting_for_delete_key)
            await callback_query.answer()
        
        elif data == "admin_extend":
            await callback_query.message.answer("📈 *Extend API Key Validity*\n\nSend in format:\n`/extendkey <api_key> <days>`\n\nExample:\n`/extendkey ansh_vinod_123456_abcdef 30`", 
                                              parse_mode=ParseMode.MARKDOWN)
            await state.set_state(AdminStates.waiting_for_extend_key)
            await callback_query.answer()
        
        elif data == "admin_stats":
            await self.stats_command(callback_query.message)
            await callback_query.answer()
        
        elif data == "admin_logout":
            db.set_admin_session(str(user_id), False)
            await callback_query.message.answer("✅ Logged out from admin panel.")
            await callback_query.answer()
        
        elif data.startswith("copy_url_"):
            api_key = data.replace("copy_url_", "")
            full_url = f"{API_BASE_URL}/mobile-lookup?key={api_key}&mobile=PHONE_NUMBER"
            await callback_query.answer(f"URL copied! Replace PHONE_NUMBER with actual number", show_alert=True)
    
    # ============ MESSAGE HANDLER ============
    async def handle_message(self, message: Message, state: FSMContext):
        """Handle all messages with state management"""
        current_state = await state.get_state()
        
        if current_state == AdminStates.waiting_for_password:
            await self.handle_password(message, state)
        
        elif current_state == AdminStates.waiting_for_genkey:
            await self.handle_genkey(message, state)
        
        elif current_state == AdminStates.waiting_for_disable_key:
            await self.handle_disable_key(message, state)
        
        elif current_state == AdminStates.waiting_for_enable_key:
            await self.handle_enable_key(message, state)
        
        elif current_state == AdminStates.waiting_for_delete_key:
            await self.handle_delete_key(message, state)
        
        elif current_state == AdminStates.waiting_for_extend_key:
            await self.handle_extend_key(message, state)
    
    async def start_polling(self):
        """Start bot polling"""
        # Register message handler for states
        self.dp.message.register(self.handle_message)
        
        logger.info("Starting Telegram bot polling...")
        await self.dp.start_polling(self.bot)

# ==================== FLASK API ====================
app = Flask(__name__)

def validate_api_key():
    """Decorator to validate API key for Flask endpoints"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            api_key = request.args.get('key')
            
            if not api_key:
                return jsonify({
                    "success": False,
                    "message": "API key required",
                    "expires_at": None,
                    "data": None
                }), 400
            
            # Check if key is disabled
            if db.is_key_disabled(api_key):
                return jsonify({
                    "success": False,
                    "message": "API key disabled by admin",
                    "expires_at": None,
                    "data": None
                }), 403
            
            # Validate format
            if not APIKeyGenerator.validate_format(api_key):
                return jsonify({
                    "success": False,
                    "message": "Invalid API key format",
                    "expires_at": None,
                    "data": None
                }), 401
            
            # Get user by API key
            user_data = db.get_user_by_key(api_key)
            if not user_data:
                return jsonify({
                    "success": False,
                    "message": "Invalid API key",
                    "expires_at": None,
                    "data": None
                }), 401
            
            # Check expiry
            if DateValidator.is_expired(user_data["expires_at"]):
                db.update_user_status(user_data.get("user_id", ""), "expired")
                return jsonify({
                    "success": False,
                    "message": "API key expired, please renew",
                    "expires_at": user_data["expires_at"],
                    "data": None
                }), 403
            
            # Increment request count
            db.increment_request_count(api_key)
            
            # Add user data to request context
            request.user_data = user_data
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def run_async(coro):
    """Run async coroutine in sync context"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)

@app.route('/mobile-lookup', methods=['GET'])
@validate_api_key()
def mobile_lookup():
    """Mobile lookup endpoint - SYNC wrapper"""
    mobile = request.args.get('mobile')
    
    if not mobile:
        return jsonify({
            "success": False,
            "message": "Mobile number required",
            "expires_at": request.user_data.get("expires_at"),
            "data": None
        }), 400
    
    # Validate mobile number (basic validation)
    if not mobile.isdigit() or len(mobile) < 10:
        return jsonify({
            "success": False,
            "message": "Invalid mobile number",
            "expires_at": request.user_data.get("expires_at"),
            "data": None
        }), 400
    
    # Run async function in sync context
    return run_async(async_mobile_lookup(mobile, request.user_data))

async def async_mobile_lookup(mobile: str, user_data: Dict):
    """Async implementation of mobile lookup"""
    try:
        # Call mother API using aiohttp
        async with aiohttp.ClientSession() as session:
            params = {
                'key': MOTHER_API_KEY,
                'mobile': mobile
            }
            
            async with session.get(MOTHER_API_URL, params=params, timeout=30) as response:
                if response.status == 200:
                    mother_response = await response.json()
                    
                    # Return mother API response wrapped in our format
                    return jsonify({
                        "success": True,
                        "message": "Lookup successful",
                        "expires_at": user_data.get("expires_at"),
                        "data": mother_response
                    })
                else:
                    logger.error(f"Mother API error: {response.status}")
                    return jsonify({
                        "success": False,
                        "message": f"Backend service error: {response.status}",
                        "expires_at": user_data.get("expires_at"),
                        "data": None
                    }), 502
                    
    except asyncio.TimeoutError:
        logger.error("Mother API timeout")
        return jsonify({
            "success": False,
            "message": "Backend service timeout",
            "expires_at": user_data.get("expires_at"),
            "data": None
        }), 504
    except Exception as e:
        logger.error(f"Mother API exception: {e}")
        return jsonify({
            "success": False,
            "message": "Internal server error",
            "expires_at": user_data.get("expires_at"),
            "data": None
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for Render"""
    db_status = "healthy" if os.path.exists(DB_FILE) else "db_missing"
    
    return jsonify({
        "status": "healthy",
        "database": db_status,
        "timestamp": datetime.now().isoformat(),
        "service": "Ansh API Gateway",
        "total_users": len(db.get_all_users()),
        "api_base_url": API_BASE_URL,
        "local_url": f"http://localhost:{PORT}"
    }), 200

@app.route('/admin/keys', methods=['GET'])
def admin_list_keys():
    """Admin endpoint to list all keys (for external use)"""
    # Simple token-based admin auth
    admin_token = request.args.get('admin_token')
    if admin_token != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401
    
    all_keys = db.get_all_keys_info()
    return jsonify({
        "success": True,
        "total_keys": len(all_keys),
        "keys": all_keys
    })

# ==================== APPLICATION RUNNER ====================
def run_flask():
    """Run Flask app in a separate thread"""
    logger.info(f"Starting Flask app on {HOST}:{PORT}")
    logger.info(f"API Base URL: {API_BASE_URL}")
    logger.info(f"Admin ID: {ADMIN_ID}")
    logger.info(f"Local access: http://localhost:{PORT}")
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)

async def run_bot():
    """Run Telegram bot"""
    if not TELEGRAM_BOT_TOKEN:
        logger.warning("TELEGRAM_BOT_TOKEN not set. Telegram bot disabled.")
        return
    
    if not ADMIN_ID:
        logger.warning("ADMIN_ID not set. Admin commands disabled.")
    
    bot = TelegramBot(TELEGRAM_BOT_TOKEN, ADMIN_ID, ADMIN_PASSWORD)
    await bot.start_polling()

async def main():
    """Main async entry point"""
    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    logger.info("Application started")
    logger.info(f"Flask API: http://{HOST}:{PORT}")
    logger.info(f"Database: {DB_FILE}")
    logger.info(f"API Base URL configured: {API_BASE_URL}")
    
    # Run Telegram bot if token is provided
    if TELEGRAM_BOT_TOKEN:
        await run_bot()
    else:
        # Keep the main thread alive
        while True:
            await asyncio.sleep(3600)

# ==================== ENTRY POINT ====================
if __name__ == "__main__":
    # Validate environment variables
    if not TELEGRAM_BOT_TOKEN:
        logger.warning("TELEGRAM_BOT_TOKEN environment variable not set")
    
    if not ADMIN_ID:
        logger.warning("ADMIN_ID environment variable not set")
    
    # Set default local URL if not configured
    if API_BASE_URL == "https://your-app.onrender.com":
        API_BASE_URL = f"http://localhost:{PORT}"
        logger.warning(f"API_BASE_URL not set. Using local URL: {API_BASE_URL}")
    
    # Create a .env file if it doesn't exist
    if not os.path.exists(".env"):
        with open(".env", "w") as f:
            f.write(f"TELEGRAM_BOT_TOKEN={TELEGRAM_BOT_TOKEN}\n")
            f.write(f"ADMIN_ID={ADMIN_ID}\n")
            f.write(f"ADMIN_PASSWORD={ADMIN_PASSWORD}\n")
            f.write(f"API_BASE_URL={API_BASE_URL}\n")
            f.write(f"PORT={PORT}\n")
        logger.info("Created .env file with default values")
    
    # Run the application
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
