import os
import asyncio
import requests
import logging
from telegram import Update, Bot, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode
from telegram.ext import Application, filters, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_groq import ChatGroq
import base64
import time
from dotenv import load_dotenv

load_dotenv()
# Enable logging
logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

api_key = os.getenv("CHAT_GROQ")
model = ChatGroq(model="llama-3.3-70b-versatile", api_key=api_key)
virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")

# Bot token
telegram_bot_token = os.getenv("TELEGRAM_TOKEN")
bot = Bot(token=telegram_bot_token)

user_memory = {}
monitoring_tasks = {}

#interactive menu
def build_menu():
    keyboard = [
        [InlineKeyboardButton("Check Scam", callback_data='check_scam'),
         InlineKeyboardButton("Verify Token", callback_data='verify_token')],
        [InlineKeyboardButton("Scan URL", callback_data='scan_url'),
         InlineKeyboardButton("Monitor Token", callback_data='monitor_token')],
        [InlineKeyboardButton("Report Suspicious", callback_data='report_suspicious'),
         InlineKeyboardButton("Help", callback_data='help')]
    ]
    return InlineKeyboardMarkup(keyboard)

# Start menu
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    user_memory[user.id] = {'conversation': [], 'reports': []}
    welcome_message = (
        f"Hi {user.first_name}! I’m Agent Cypher 🤖, your crypto and web3 security assistant.\n\n"
        "I can:\n"
        "- Check for scams\n"
        "- Verify tokens\n"
        "- Scan URLs for threats\n"
        "- Monitor tokens for risks\n"
        "- Report suspicious activity\n\n"
        "Choose an action below or type a command to begin!"
    )
    await update.message.reply_text(welcome_message)
    await update.message.reply_text("Menu:", reply_markup=build_menu())

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    help_text = (
        "**Available Commands:**\n\n"
        "- `/check_scam <text>`: Analyze if a message might be a scam.\n"
        "- `/verify_token <address>`: Verify a token’s details.\n"
        "- `/scan_url <url>`: Check a URL for safety.\n"
        "- `/monitor <token_address>`: Subscribe to risk alerts for a token.\n"
        "- `/report <token_address> <reason>`: Flag a token as suspicious.\n"
        "- `/menu`: Show the action menu.\n"
        "- `/cancel`: Reset any ongoing action.\n\n"
        "You can also ask me security questions directly!\n"
        "Join our community: https://t.me/+wOob4U1U2tplNmFk"
    )
    await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

# Menu command
async def menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("Choose an action:", reply_markup=build_menu())

# Cancel command
async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if 'action' in user_memory.get(user_id, {}):
        del user_memory[user_id]['action']
        await update.message.reply_text("Action cancelled. What’s next?")
    else:
        await update.message.reply_text("Nothing to cancel!")

# Handle button clicks
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    if query.data == 'check_scam':
        user_memory[user_id]['action'] = 'check_scam'
        await query.edit_message_text("Please send the text to check for scams.")
    elif query.data == 'verify_token':
        user_memory[user_id]['action'] = 'verify_token'
        await query.edit_message_text("Please send the token address to verify.")
    elif query.data == 'scan_url':
        user_memory[user_id]['action'] = 'scan_url'
        await query.edit_message_text("Please send the URL to scan.")
    elif query.data == 'monitor_token':
        user_memory[user_id]['action'] = 'monitor_token'
        await query.edit_message_text("Please send the token address to monitor.")
    elif query.data == 'report_suspicious':
        user_memory[user_id]['action'] = 'report_suspicious'
        await query.edit_message_text("Please send the token address and a reason (e.g., /report <address> <reason>).")
    elif query.data == 'help':
        await help_command(update, context)

# Scam check logic
async def check_scam_logic(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
    try:
        system_message = SystemMessage(
            content="You are a scam detector. Respond with 'Scam:' or 'Not a Scam:' and provide a brief explanation."
        )
        human_message = HumanMessage(content=f"Analyze this: {text}")
        response = model(messages=[system_message, human_message])
        reply = f"**🕵️ Scam Analysis Result:**\n\n{response.content}\n\nWhat else can I assist you with?"
        await update.message.reply_text(reply, parse_mode=ParseMode.MARKDOWN)
    except Exception as e:
        logger.error(f"Error checking scam: {e}")
        await update.message.reply_text("Sorry, I couldn’t analyze that. Try again!")

# Token verification logic with wallet profiling all with rugcheck
async def verify_token_logic(update: Update, context: ContextTypes.DEFAULT_TYPE, token_address: str) -> None:
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
    try:
        url = f"https://api.rugcheck.xyz/v1/tokens/{token_address}/report"
        response = requests.get(url, headers={"Accept": "application/json"})
        if response.status_code == 200:
            token_data = response.json()
            reply = f"**✅ Token Verification Summary**\n\n"
            reply += f"- **Token Name**: {token_data.get('tokenMeta', {}).get('name', 'N/A')}\n"
            reply += f"- **Symbol**: {token_data.get('tokenMeta', {}).get('symbol', 'N/A')}\n"
            reply += f"- **Risk Score**: {token_data.get('score', 'N/A')}\n"
            reply += f"- **Market Cap**: {token_data.get('token', {}).get('market_cap', 'N/A')}\n"
            reply += f"- **Total Liquidity**: ${token_data.get('totalMarketLiquidity', 'N/A'):,.2f}\n"
            reply += f"- **Total LP Providers**: {token_data.get('totalLPProviders', 'N/A')}\n"
            # Basic wallet profiling
            top_holders = token_data.get('topHolders', [])
            if top_holders:
                reply += "\n**🔍 Top Holders Analysis**:\n"
                for holder in top_holders[:3]:  # Limit to top 3 for brevity
                    wallet = holder.get('address', 'N/A')
                    percentage = holder.get('percentage', 0)
                    reply += f"- Wallet {wallet[:6]}...: {percentage:.2f}% of supply\n"
                if len(top_holders) <= 5 and sum(h.get('percentage', 0) for h in top_holders) > 50:
                    reply += "⚠️ High concentration risk: Few wallets hold most tokens!\n"
            if token_data.get('risks', []):
                reply += "\n**⚠️ Risks Detected**:\n" + "\n".join(
                    f"- {risk.get('name', 'N/A')}: {risk.get('description', 'N/A')}" for risk in token_data.get('risks', [])
                )
            else:
                reply += "\n✅ No significant risks found."
            await update.message.reply_text(reply, parse_mode=ParseMode.MARKDOWN)
            system_message = SystemMessage(
                content="Explain token verification results in simple terms using bullet points. Avoid jargon."
            )
            human_message = HumanMessage(content=f"Explain this:\n\n{reply}")
            response = model(messages=[system_message, human_message])
            await update.message.reply_text(f"**🤖 Simplified Explanation:**\n\n{response.content}", parse_mode=ParseMode.MARKDOWN)
        else:
            await update.message.reply_text("❌ Couldn’t fetch token details. Check the address!")
    except Exception as e:
        logger.error(f"Error verifying token: {e}")
        await update.message.reply_text("❌ Token verification failed. Try again later.")

# URL scan logic
async def scan_url_logic(update: Update, context: ContextTypes.DEFAULT_TYPE, url: str) -> None:
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        url_data = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": virustotal_api_key},
        ).json()
        if "error" not in url_data:
            stats = url_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            reply = f"**🔍 URL Analysis Results**\n\n"
            reply += f"- Harmless: {stats.get('harmless', 0)}\n"
            reply += f"- Malicious: {stats.get('malicious', 0)}\n"
            reply += f"- Suspicious: {stats.get('suspicious', 0)}\n"
            reply += f"- Undetected: {stats.get('undetected', 0)}\n"
            reply += f"\n**Risk Summary:**\n"
            reply += f"- Malicious/Suspicious Reports: {stats.get('malicious', 0) + stats.get('suspicious', 0)}\n"
            reply += f"- Risk Score: {round((stats.get('malicious', 0) + stats.get('suspicious', 0)) / max(sum(stats.values()), 1) * 100, 2)}%\n"
            await update.message.reply_text(reply, parse_mode=ParseMode.MARKDOWN)
            system_message = SystemMessage(
                content="Explain URL scan results in simple terms using bullet points."
            )
            human_message = HumanMessage(content=f"Explain this:\n\n{reply}")
            response = model(messages=[system_message, human_message])
            await update.message.reply_text(f"**🤖 Simplified Explanation:**\n\n{response.content}", parse_mode=ParseMode.MARKDOWN)
        else:
            await update.message.reply_text("URL not in VirusTotal yet. Submitted for scanning—check back soon!")
    except Exception as e:
        logger.error(f"Error scanning URL: {e}")
        await update.message.reply_text("URL scan failed. Try again!")

# Monitor token logic
async def monitor_token_logic(update: Update, context: ContextTypes.DEFAULT_TYPE, token_address: str) -> None:
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    if user_id not in monitoring_tasks:
        monitoring_tasks[user_id] = {}
    monitoring_tasks[user_id][token_address] = time.time()
    await update.message.reply_text(f"Monitoring started for token {token_address}. I’ll notify you of any risks!")
    asyncio.create_task(monitor_task(user_id, chat_id, token_address, context))

async def monitor_task(user_id: int, chat_id: int, token_address: str, context: ContextTypes.DEFAULT_TYPE):
    while token_address in monitoring_tasks.get(user_id, {}):
        try:
            url = f"https://api.rugcheck.xyz/v1/tokens/{token_address}/report"
            response = requests.get(url, headers={"Accept": "application/json"})
            if response.status_code == 200:
                token_data = response.json()
                risks = token_data.get('risks', [])
                if risks:
                    alert = f"⚠️ Alert for {token_address}:\n" + "\n".join(
                        f"- {risk.get('name', 'N/A')}: {risk.get('description', 'N/A')}" for risk in risks
                    )
                    await context.bot.send_message(chat_id=chat_id, text=alert, parse_mode=ParseMode.MARKDOWN)
                    del monitoring_tasks[user_id][token_address]  # Stop monitoring after alert
            await asyncio.sleep(300)  # Check every 5 minutes
        except Exception as e:
            logger.error(f"Error monitoring token: {e}")
            await context.bot.send_message(chat_id=chat_id, text="Monitoring failed. Try again!")
            break

# Report suspicious logic
async def report_suspicious_logic(update: Update, context: ContextTypes.DEFAULT_TYPE, token_address: str, reason: str) -> None:
    user_id = update.effective_user.id
    user_memory[user_id].setdefault('reports', []).append({'token': token_address, 'reason': reason})
    await update.message.reply_text(f"Reported {token_address} as suspicious: {reason}. Thanks for contributing!")
    # Simple community risk summary
    all_reports = [r for u in user_memory.values() for r in u.get('reports', []) if r['token'] == token_address]
    if len(all_reports) > 1:
        await update.message.reply_text(f"Community reports for {token_address}: {len(all_reports)} flags.")

# Message handler
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    user_data = user_memory.get(user_id, {})
    text = update.message.text
    if 'action' in user_data:
        action = user_data['action']
        if action == 'check_scam':
            await check_scam_logic(update, context, text)
        elif action == 'verify_token':
            await verify_token_logic(update, context, text)
        elif action == 'scan_url':
            await scan_url_logic(update, context, text)
        elif action == 'monitor_token':
            await monitor_token_logic(update, context, text)
        elif action == 'report_suspicious':
            parts = text.split(" ", 1)
            if len(parts) < 2:
                await update.message.reply_text("Please provide a reason: /report <address> <reason>")
            else:
                await report_suspicious_logic(update, context, parts[0], parts[1])
        del user_data['action']
    else:
        if "http" in text or "www." in text:
            await update.message.reply_text(
                "I noticed a URL! Want me to scan it? Use /scan_url <your_url>."
            )
        else:
            await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
            conversation = user_data.get('conversation', [])
            try:
                messages = [
                    SystemMessage(
                        content="You are Agent Cypher, a crypto and web3 security assistant. Keep responses concise and security-focused."
                    )
                ]
                if conversation:
                    messages.extend([HumanMessage(content=msg) for msg in conversation[-4:]])
                messages.append(HumanMessage(content=text))
                response = model.invoke(messages)
                conversation.append(text)
                conversation.append(response.content)
                user_memory[user_id]['conversation'] = conversation[-10:]
                await update.message.reply_text(response.content)
            except Exception as e:
                logger.error(f"Error handling message: {e}")
                await update.message.reply_text("I’m having trouble. Try a command like /check_scam!")

# Command handlers
async def check_scam(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Oops! Please use /check_scam <text>.")
        return
    await check_scam_logic(update, context, " ".join(context.args))

async def verify_token(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Please use /verify_token <address>.")
        return
    await verify_token_logic(update, context, context.args[0])

async def scan_url(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Please use /scan_url <url>.")
        return
    await scan_url_logic(update, context, " ".join(context.args))

async def monitor(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Please use /monitor <token_address>.")
        return
    await monitor_token_logic(update, context, context.args[0])

async def report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if len(context.args) < 2:
        await update.message.reply_text("Please use /report <token_address> <reason>.")
        return
    await report_suspicious_logic(update, context, context.args[0], " ".join(context.args[1:]))

# Main function
def main() -> None:
    application = Application.builder().token(telegram_bot_token).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("menu", menu))
    application.add_handler(CommandHandler("cancel", cancel))
    application.add_handler(CommandHandler("check_scam", check_scam))
    application.add_handler(CommandHandler("verify_token", verify_token))
    application.add_handler(CommandHandler("scan_url", scan_url))
    application.add_handler(CommandHandler("monitor", monitor))
    application.add_handler(CommandHandler("report", report))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.run_polling()

if __name__ == "__main__":
    asyncio.run(main())