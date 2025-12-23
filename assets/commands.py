from aiogram import Router, types
from aiogram.filters import Command
from assets.cheker import ip_checker, url_cheker, domain_checker, send_file_to_virustotal, analysis_report
from aiogram.fsm.context import FSMContext
from assets.dialog import IPScan, URLScan, DOMAINScan, FILEScan, URLandFILEScan
import asyncio
from pathlib import Path

route=Router()

@route.message(Command('start'))
async def start(message: types.Message):
    keyboard = types.InlineKeyboardMarkup(
        inline_keyboard=[
            [types.InlineKeyboardButton(text='IP SCAN', callback_data='ip_scan')],
            [types.InlineKeyboardButton(text='FILE CHECK', callback_data='file_check')],
            [types.InlineKeyboardButton(text='URL CHECK', callback_data='url_check')],
            [types.InlineKeyboardButton(text='DOMAIN CHECK', callback_data='domain_check')],
            [types.InlineKeyboardButton(text='URL / FILE ANALYSIS', callback_data='urlfile_analysis')],
            [types.InlineKeyboardButton(text='ABOUT', callback_data='about')],
        ]
    )
    await message.answer(
        'Welcome! This bot lets you check your files using the VirusTotal system 🛡️\n\n'
        'Please choose what interests you from the options below ⬇️',
        reply_markup=keyboard
    )

DOWNLOAD_DIR = Path("downloads")
DOWNLOAD_DIR.mkdir(exist_ok=True)

@route.callback_query(lambda c: c.data == 'about')
async def about(callback: types.CallbackQuery):
    about_text = (
        "👋 Hi! I'm Arkhyp, this bot helps you check IPs, URLs, and domains using VirusTotal API\n\n"
        "Check security reports: <a href='https://www.virustotal.com'>VirusTotal</a>\n"
        "My projects: <a href='https://github.com/arhkypGitProject/ArkhypDanylov-Portfolio'>GitHub</a>\n\n"
        "⚠️ Informational only, not an antivirus!"
    )
    await callback.message.answer(
        about_text,
        parse_mode="HTML",
        disable_web_page_preview=True
    )


@route.callback_query(lambda c: c.data == 'ip_scan')
async def ip_scan(callback: types.CallbackQuery, state: FSMContext):
    await callback.message.answer("Send the IP for checking")
    await state.set_state(IPScan.waiting_for_ip)

@route.message(IPScan.waiting_for_ip)
async def process_ip(message: types.Message, state: FSMContext):
    ip = message.text.strip()

    await message.answer("Checking IP, please wait...")

    try:
        result = await asyncio.to_thread(ip_checker, ip)
    except Exception:
        await message.answer("❌ Error while checking IP")
        await state.clear()
        return

    if "error" in result:
        await message.answer("❌ IP report not found or API error")
        await state.clear()
        return

    text = (
        f"🌐 VirusTotal IP Report\n"
        f"IP: {result['ip']}\n"
        f"ASN: {result['asn']} ({result['as_owner']})\n"
        f"Country: {result['country']}\n\n"
        "Last Analysis:\n"
        f"-Malicious: {result['malicious']}\n"
        f"-Suspicious: {result['suspicious']}\n"
        f"-Harmless: {result['harmless']}\n"
        f"-Undetected: {result['undetected']}\n\n"
        "Source: VirusTotal.com\n"
        "⚠️ Informational only, not an antivirus!"
    )

    await message.answer(text)
    await state.clear()

@route.callback_query(lambda c: c.data == 'url_check')
async def url_scan(callback: types.CallbackQuery, state: FSMContext):
    await callback.message.answer("Send the URL for checking")
    await state.set_state(URLScan.waiting_for_url)

@route.message(URLScan.waiting_for_url)
async def url_process(message: types.Message, state: FSMContext):
    url = message.text.strip()

    await message.answer("🔍 Checking URL, please wait...")

    try:
        result = await asyncio.to_thread(url_cheker, url)
    except Exception:
        await message.answer("❌ Error while checking URL")
        await state.clear()
        return

    if "error" in result:
        await message.answer("❌ URL report not found or API error")
        await state.clear()
        return

    text = (
        f"🌐 VirusTotal URL Report\n"
        f"URL: {result['url']}\n"
        f"Analysis ID: {result['id']}\n\n"
        "Analysis Status:\n"
        "The URL has been successfully submitted for analysis!\n\n"
        "Source: VirusTotal.com\n"
        "⚠️ Informational only, not an antivirus!"
    )

    await message.answer(text)
    await state.clear()

@route.callback_query(lambda c: c.data == 'domain_check')
async def domain_scan(callback: types.CallbackQuery, state: FSMContext):
    await callback.message.answer("Send the DOMAIN for checking")
    await state.set_state(DOMAINScan.waiting_for_domain)

@route.message(DOMAINScan.waiting_for_domain)
async def domain_process(message: types.Message, state: FSMContext):
    domain = message.text.strip()

    await message.answer("🔍 Checking DOMAIN, please wait...")

    try:
        result = await asyncio.to_thread(domain_checker, domain)
    except Exception:
        await message.answer("❌ Error while checking DOMAIN")
        await state.clear()
        return

    if "error" in result:
        await message.answer("❌ DOMAIN report not found or API error")
        await state.clear()
        return

    text = (
        f"🌐 VirusTotal Domain Report\n"
        f"Domain: {result['domain']}\n"
        f"Registrar: {result.get('registrar', 'Unknown')}\n"
        f"Reputation: {result.get('reputation', 'Unknown')}\n"
        f"Total votes - Harmless: {result.get('total_votes', {}).get('harmless', 0)}, Malicious: {result.get('total_votes', {}).get('malicious', 0)}\n\n"
        "Last Analysis Stats:\n"
        f"-Malicious: {result.get('last_analysis_stats', {}).get('malicious', 0)}\n"
        f"-Suspicious: {result.get('last_analysis_stats', {}).get('suspicious', 0)}\n"
        f"-Harmless: {result.get('last_analysis_stats', {}).get('harmless', 0)}\n"
        f"-Undetected: {result.get('last_analysis_stats', {}).get('undetected', 0)}\n\n"
        "Source: VirusTotal.com\n"
        "⚠️Informational only, not an antivirus!"
    )
    await message.answer(text)
    await state.clear()

@route.callback_query(lambda c: c.data == "file_check")
async def file_scan_callback(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer()
    await callback.message.answer("Send the file you want to scan")
    await state.set_state(FILEScan.waiting_for_file)


@route.message(FILEScan.waiting_for_file, lambda message: message.document)
async def handle_file(message: types.Message, state: FSMContext):
    document = message.document
    file_name = document.file_name
    file_size = document.file_size
    file_id = document.file_id

    file_path = DOWNLOAD_DIR / file_name

    await message.answer("Downloading file...")

    try:
        file = await message.bot.get_file(file_id)
        await message.bot.download_file(file.file_path, destination=file_path)

        await message.answer(
            f"File downloaded\nName: {file_name}\nSize: {round(file_size / 1024 / 1024, 2)} MB"
        )
        result = await asyncio.to_thread(send_file_to_virustotal, file_path)

        report_text = (
            f"🌐 VirusTotal File Report\n"
            f"File: {file_name}\n"
            f"Size: {round(file_size / 1024 / 1024, 2)} MB\n\n"
            f"Total votes - Harmless: {result.get('total_votes', {}).get('harmless', 0)}, "
            f"Malicious: {result.get('total_votes', {}).get('malicious', 0)}\n\n"
            "Last Analysis Stats:\n"
            f"-Malicious: {result.get('last_analysis_stats', {}).get('malicious', 0)}\n"
            f"-Suspicious: {result.get('last_analysis_stats', {}).get('suspicious', 0)}\n"
            f"-Harmless: {result.get('last_analysis_stats', {}).get('harmless', 0)}\n"
            f"-Undetected: {result.get('last_analysis_stats', {}).get('undetected', 0)}\n\n"
            "⚠️ Informational only, not an antivirus!"
        )

        await message.answer(report_text)

    except Exception as e:
        await message.answer(f"Error: {e}")

    finally:
        if file_path.exists():
            file_path.unlink()
            print(f"Temporary file deleted: {file_name}")
        await state.clear()

@route.callback_query(lambda c: c.data == "urlfile_analysis")
async def analysis_callback(callback: types.CallbackQuery, state: FSMContext):
    await callback.message.answer("Please send the Analysis ID:")
    await state.set_state(URLandFILEScan.waiting_for_id)

@route.message(lambda message: True, URLandFILEScan.waiting_for_id)
async def check_analysis_id(message: types.Message, state: FSMContext):
    analysis_id = message.text.strip()
    await message.answer("Fetching analysis report...")

    try:
        result = await asyncio.to_thread(analysis_report, analysis_id)

        report_text = (
            f"🌐 VirusTotal Analysis Report\n"
            f"Status: {result['status']}\n"
            f"-Malicious: {result['malicious']}\n"
            f"-Suspicious: {result['suspicious']}\n"
            f"-Harmless: {result['harmless']}\n"
            f"-Undetected: {result['undetected']}\n"
            f"Source: VirusTotal.com\n"
            "⚠️ Informational only, not an antivirus!"
        )
        await message.answer(report_text, parse_mode="Markdown", disable_web_page_preview=True)

    except Exception as e:
        await message.answer(f"❌ Error: {e}")
    finally:
        await state.clear()
