import os
import asyncio
import requests
import logging
import base64
from telegram import Update, Bot
from telegram.ext import Application, filters, CommandHandler, MessageHandler, ContextTypes
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_groq import ChatGroq
from uuid import uuid4

# Enable logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# Configuration
API_KEY = os.getenv("GROK_API_KEY", "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")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "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")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "7701419281:AAF5xDnnpUs6ZvRw8cu_IMc6S93LoyIItgI")

# Validate environment variables
if not all([API_KEY, VIRUSTOTAL_API_KEY, TELEGRAM_BOT_TOKEN]):
    raise ValueError("Missing required environment variables")

# Initialize Groq model
model = ChatGroq(model="llama-3.3-70b-versatile", api_key=API_KEY)
bot = Bot(token=TELEGRAM_BOT_TOKEN)

# In-memory storage
user_memory = {}  # Store user conversation history
community_flags = {}  # Store community-flagged tokens

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a welcome message when the /start command is issued."""
    user = update.effective_user
    user_memory[user.id] = []
    await update.message.reply_text(
        f"Hi {user.first_name}! I'm AgentCypher 🤖, built for RugCheck's hackathon. "
        "I help verify tokens, scan URLs, and detect scams using RugCheck and VirusTotal APIs. "
        "Use /help for commands or chat directly. Join our community: https://t.me/+wOob4U1U2tplNmFk"
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Display available commands."""
    await update.message.reply_text(
        "Commands:\n"
        "/check_scam <text/wallet> - Check if text is a scam.\n"
        "/verify_token <token address> - Verify token details.\n"
        "/scan_url <example.com> - Scan a URL for risks.\n"
        "/flag_token <token address> <reason> - Flag a suspicious token.\n"
        "/token_report <token address> - Generate a shareable token report.\n"
        "Chat directly for general queries!\n"
        "Community: https://t.me/+wOob4U1U2tplNmFk"
    )

async def check_scam(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Check if input text is a potential scam."""
    if not context.args:
        await update.message.reply_text("Usage: /check_scam <text>")
        return

    text = " ".join(context.args)
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
    
    try:
        system_message = SystemMessage(
            content="You are a scam detector leveraging RugCheck and X data. Respond with 'Scam:' or 'Not a Scam:' and a brief explanation."
        )
        human_message = HumanMessage(content=f"Analyze: {text}")
        response = model.invoke([system_message, human_message])
        await update.message.reply_text(f"🕵️ Analysis:\n{response.content}")
    except Exception as e:
        logger.error(f"Error checking scam: {e}")
        await update.message.reply_text("Error processing request.")

async def verify_token(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Verify a token using RugCheck API."""
    if not context.args:
        await update.message.reply_text("Usage: /verify_token <token address>")
        return

    token_address = context.args[0]
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
    
    try:
        response = requests.get(
            f"https://api.rugcheck.xyz/v1/tokens/{token_address}/report",
            headers={"Accept": "application/json"}
        )
        
        if response.status_code == 200:
            token_data = response.json()
            reply = (
                f"✅ **Token Verification**\n\n"
                f"🔹 Name: {token_data.get('tokenMeta', {}).get('name', 'N/A')}\n"
                f"🔹 Symbol: {token_data.get('tokenMeta', {}).get('symbol', 'N/A')}\n"
                f"🔹 Risk Score: {token_data.get('score', 'N/A')}\n"
                f"🔹 Market Cap: {token_data.get('token', {}).get('market_cap', 'N/A')}\n"
                f"🔹 Liquidity: ${token_data.get('totalMarketLiquidity', 0):,.2f}\n"
                f"🔹 LP Providers: {token_data.get('totalLPProviders', 'N/A')}\n"
            )
            
            risks = token_data.get('risks', [])
            reply += "\n⚠️ **Risks**:\n" + (
                "".join(f"  - {risk.get('name')}: {risk.get('description')} (Score: {risk.get('score')})\n" for risk in risks)
                if risks else "  No significant risks.\n"
            )
            
            top_holders = token_data.get('topHolders', [])
            if top_holders:
                reply += f"\n🔹 Top Holder:\n  - Address: {top_holders[0].get('address', 'N/A')}\n  - {top_holders[0].get('pct', 'N/A')}%"
            
            await update.message.reply_text(reply)
            
            # Simplified explanation
            system_message = SystemMessage(
                content="Explain token verification results in simple terms to advise on investment safety."
            )
            response = model.invoke([system_message, HumanMessage(content=reply)])
            await update.message.reply_text(f"🤖 Explanation:\n{response.content}")
        else:
            await update.message.reply_text("❌ Invalid token address.")
    except Exception as e:
        logger.error(f"Error verifying token: {e}")
        await update.message.reply_text("❌ Error verifying token.")

async def scan_url(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Scan a URL using VirusTotal API."""
    if not context.args:
        await update.message.reply_text("Usage: /scan_url <url>")
        return

    url = " ".join(context.args)
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
    
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY}
        ).json()
        
        if "error" not in response:
            stats = response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            reply = (
                f"🔍 URL Analysis\n\n"
                f"  Harmless: {stats.get('harmless', 0)}\n"
                f"  Malicious: {stats.get('malicious', 0)}\n"
                f"  Suspicious: {stats.get('suspicious', 0)}\n"
                f"  Risk Score: {round((stats.get('malicious', 0) + stats.get('suspicious', 0)) / max(sum(stats.values()), 1) * 100, 2)}%\n"
            )
            await update.message.reply_text(reply)
            
            system_message = SystemMessage(
                content="Explain URL scan results in simple terms to advise on safety."
            )
            response = model.invoke([system_message, HumanMessage(content=reply)])
            await update.message.reply_text(f"🤖 Explanation:\n{response.content}")
        else:
            await update.message.reply_text("URL not found. Submitted for scanning.")
    except Exception as e:
        logger.error(f"Error scanning URL: {e}")
        await update.message.reply_text("Error scanning URL.")

async def flag_token(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Allow users to flag suspicious tokens for community review."""
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /flag_token <token address> <reason>")
        return

    token_address = context.args[0]
    reason = " ".join(context.args[1:])
    user = update.effective_user
    
    community_flags.setdefault(token_address, []).append({
        "user_id": user.id,
        "username": user.username or user.first_name,
        "reason": reason,
        "timestamp": update.message.date.isoformat()
    })
    
    await update.message.reply_text(
        f"🚩 Token {token_address} flagged for: {reason}\n"
        f"Community flags: {len(community_flags[token_address])}\n"
        "Thank you for contributing to community safety!"
    )

async def token_report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Generate a shareable token report."""
    if not context.args:
        await update.message.reply_text("Usage: /token_report <token address>")
        return

    token_address = context.args[0]
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
    
    try:
        response = requests.get(
            f"https://api.rugcheck.xyz/v1/tokens/{token_address}/report",
            headers={"Accept": "application/json"}
        )
        
        if response.status_code == 200:
            token_data = response.json()
            report = (
                f"📊 **RugCheck Token Report**\n\n"
                f"🔹 Token: {token_data.get('tokenMeta', {}).get('name', 'N/A')} ({token_data.get('tokenMeta', {}).get('symbol', 'N/A')})\n"
                f"🔹 Address: {token_address}\n"
                f"🔹 Risk Score: {token_data.get('score', 'N/A')}\n"
                f"🔹 Community Flags: {len(community_flags.get(token_address, []))}\n"
                f"🔹 Share: Post this report on X and tag @Rugcheckxyz for visibility!\n"
            )
            await update.message.reply_text(report)
        else:
            await update.message.reply_text("❌ Invalid token address.")
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        await update.message.reply_text("❌ Error generating report.")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle general user messages."""
    user = update.effective_user
    user_message = update.message.text
    
    if user_message.lower().startswith("scan url"):
        await scan_url(update, context)
        return

    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
    conversation = user_memory.get(user.id, [])
    
    try:
        messages = [
            SystemMessage(
                content="You are AgentCypher, a RugCheck hackathon bot specializing in crypto scam detection, token verification, and URL scanning. Be concise and helpful."
            )
        ]
        messages.extend([HumanMessage(content=msg) for msg in conversation[-4:]])
        messages.append(HumanMessage(content=user_message))
        
        response = model.invoke(messages)
        conversation.extend([user_message, response.content])
        user_memory[user.id] = conversation[-10:]
        
        await update.message.reply_text(response.content)
    except Exception as e:
        logger.error(f"Error handling message: {e}")
        await update.message.reply_text("Error processing message. Try /check_scam or /scan_url.")

def main() -> None:
    """Run the bot."""
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("check_scam", check_scam))
    application.add_handler(CommandHandler("verify_token", verify_token))
    application.add_handler(CommandHandler("scan_url", scan_url))
    application.add_handler(CommandHandler("flag_token", flag_token))
    application.add_handler(CommandHandler("token_report", token_report))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    application.run_polling()

if __name__ == "__main__":
    asyncio.run(main())