import telebot
import requests
import os
import re
a

TELEGRAM_BOT_TOKEN = "8187266608:AAEUOAcHP2xUoUABwHByBE37hXFvmohS0gw"
VIRUSTOTAL_API_KEY = "5c4675336d5e0efe22fcfe9fdd3c70268170cedb03db97f592b412b5cb2bf5f5"

bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

def scan_file(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    with open(file_path, "rb") as file:
        files = {"file": file}
        response = requests.post(url, headers=headers, files=files)
    return response.json() if response.status_code == 200 else None

def scan_url(url_to_scan):
    url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url_to_scan}
    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        scan_id = response.json()["data"]["id"]
        report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        result = requests.get(report_url, headers=headers).json()
        return result
    return None

@bot.message_handler(content_types=['document', 'photo'])
def handle_file(message):
    bot.reply_to(message, "🕵️ Проверяю файл...")
    file_info = bot.get_file(message.document.file_id if message.document else message.photo[-1].file_id)
    downloaded = bot.download_file(file_info.file_path)
    filename = message.document.file_name if message.document else f"temp_image.jpg"
    with open(filename, "wb") as f: f.write(downloaded)
    result = scan_file(filename)
    os.remove(filename)

    if result:
        stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        scan_url_vt = f"https://www.virustotal.com/gui/file/{result['data']['id']}"
        if malicious > 0:
            engines = result['data']['attributes']['last_analysis_results']
            positives = [name for name, r in engines.items() if r['category'] == 'malicious']
            engine_list = ', '.join(positives)
            bot.reply_to(message, f"🚨 Вирус найден ({malicious} обнаружений)\nАнтивирусы: {engine_list}\n🔗 Отчёт: {scan_url_vt}")
        else:
            bot.reply_to(message, f"✅ Файл безопасен\n🔗 Отчёт: {scan_url_vt}")
    else:
        bot.reply_to(message, "⚠️ Не удалось проверить файл.")

@bot.message_handler(func=lambda m: True)
def check_links(message):
    urls = re.findall(r'(https?://\S+)', message.text or "")
    for link in urls:
        bot.reply_to(message, f"🔍 Проверяю ссылку: {link}")
        result = scan_url(link)
        if result:
            stats = result.get("data", {}).get("attributes", {}).get("stats", {})
            malicious = stats.get("malicious", 0)
            scan_url_vt = f"https://www.virustotal.com/gui/url/{result['data']['id']}"
            if malicious > 0:
                bot.reply_to(message, f"🚨 Опасная ссылка! ({malicious} антивирусов сработали)\n🔗 Отчёт: {scan_url_vt}")
            else:
                bot.reply_to(message, f"✅ Ссылка безопасна\n🔗 Отчёт: {scan_url_vt}")
        else:
            bot.reply_to(message, "⚠️ Не удалось проверить ссылку.")

bot.polling()
