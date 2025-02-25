import os
import json
import logging
import asyncio
import aiohttp

from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse

import aioschedule as schedule
import re
import discord
import requests
import urllib.parse
import difflib

from tools.webscreenshot import DomainProbe
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from google.oauth2.service_account import Credentials

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
SERVICE_ACCOUNT_FILE = 'ggdrive.json'
DOM_DIR = os.path.join("result", "dom")
RECORD_DIR = os.path.join("record")
STATUSES = {
    200: "200 OK",
    301: "301 Permanent Redirect",
    302: "302 Temporary Redirect",
    404: "404 Not Found",
    500: "500 Internal Server Error",
    503: "503 Service Unavailable"
}

intents = discord.Intents.default()
intents.messages = True
intents.message_content = True
bot = discord.Client(intents=intents)

CHANNEL_ID = 1307339430096273489



def getScreenshot(url):
    """Take a screenshot using an external service."""
    BASE = 'https://mini.s-shot.ru/1920x1080/JPEG/1024/Z100/?'
    url = urllib.parse.quote_plus(url)
    path = f'{url}.png'
    response = requests.get(BASE + url, stream=True, timeout=20)

    if response.status_code == 200:
        screenshot_path = f'result/screenshot/{path}'
        os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)  # Create folder if it doesn't exist
        with open(screenshot_path, 'wb') as file:
            for chunk in response:
                file.write(chunk)
        return screenshot_path
    return None

# def getScreenshot(url):
#     domains_to_probe = [url]
#     probe = DomainProbe(domains=domains_to_probe)
#     probe.run()
#     return "result/screenshot/" + probe.data[url]['screenshot']
#     # print(probe.data)
    
def authenticate_drive():
    """Authenticate and return the Google Drive API service."""
    credentials = Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=["https://www.googleapis.com/auth/drive"])
    service = build("drive", "v3", credentials=credentials)
    return service


def upload_to_drive(service, file_path, file_name, folder_id=None):
    """Upload a file to Google Drive."""
    file_metadata = {
        "name": file_name,
        "parents": [folder_id] if folder_id else []
    }
    media = MediaFileUpload(file_path, resumable=True)
    uploaded_file = service.files().create(body=file_metadata, media_body=media, fields="id").execute()
    return uploaded_file.get("id")


def save_differences_to_drive(differences, file_name, folder_id=None):
    try:
        os.makedirs(".temp", exist_ok=True)

        file_path = f".temp/{file_name}"
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(differences)

        file_name = f"[{datetime.utcnow():%Y-%m-%d %H:%M:%S}-DEFACE]" + file_name.replace("differences_", "")
        
        service = authenticate_drive()
        file_id = upload_to_drive(service, file_path, file_name, folder_id)
        print(f"File uploaded successfully. File ID: {file_id}")
        return file_id
    except Exception as e:
        print(f"Error saving to Google Drive: {e}")
        return None
    
    
def get_dom_diff(old_dom, new_dom):
    """Generate a human-readable difference between two DOMs."""
    diff = difflib.unified_diff(
        old_dom.splitlines(),
        new_dom.splitlines(),
        lineterm='',
        fromfile='Old DOM',
        tofile='New DOM'
    )
    return '\n'.join(diff)


def sanitize_filename(url):
    """Sanitize URL for file naming."""
    return url.replace("http://", "").replace("https://", "").replace("/", "_")


async def fetch_html(session, url):
    """Fetch the HTML of a URL."""
    try:
        async with session.get('http://' + url) as response:
            if response.status != 200:
                return None
            return await response.text()
    except aiohttp.ClientError as e:
        #logging.error(f"Error fetching {url}: {e}")
        return None


async def save_dom(url, dom_content):
    """Save the DOM content to a file."""
    sanitized_url = sanitize_filename(url)
    path = os.path.join(DOM_DIR, f"{sanitized_url}.html")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, 'w', encoding='utf-8') as file:
            file.write(dom_content.upper())
        logging.info(f"Saved DOM for {url}")
    except Exception as e:
        logging.error(f"Error saving DOM for {url}: {e}")


async def load_dom(url):
    """Load the DOM content from a file."""
    sanitized_url = sanitize_filename(url)
    path = os.path.join(DOM_DIR, f"{sanitized_url}.html")
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as file:
                return file.read()
        except Exception as e:
            logging.error(f"Error loading DOM for {url}: {e}")
    return None


def get_kgram_hashes(url: str, k_gram: int, basis: int):
    """Generate k-gram hashes for URL."""
    hashes = []
    powers = [basis ** i for i in range(k_gram, -1, -1)]
    
    for start in range(len(url) - k_gram + 1):
        hash_value = 0
        for i in range(k_gram):
            hash_value += ord(url[start + i]) * powers[i]
        hashes.append(hash_value)
    
    return hashes


def preprocess_text(html_text):
    """Preprocess HTML by removing non-alphanumeric characters."""
    cleaned_text = re.sub(r'[^a-zA-Z0-9]', '', html_text)
    return cleaned_text


def get_jaccard_similarity(hashes1, hashes2):
    """Calculate the Jaccard Similarity between two sets of hashes."""
    set1 = set(hashes1)
    set2 = set(hashes2)
    intersection = set1.intersection(set2)
    union = set1.union(set2)
    similarity = (len(intersection) / len(union)) * 100
    return similarity


async def send_deface_report(url, screenshot_path, differences):
    """Send a deface report with a screenshot and differences to Discord."""
    embed = discord.Embed(
        title="🚨 Web Defacement Alert 🚨",
        description="A website has been defaced.",
        color=discord.Color.red(),
        timestamp=datetime.utcnow()
    )
    embed.add_field(name="Defaced URL", value=f"[{url}]({url})", inline=False)
    embed.add_field(name="Reported At", value=f"{datetime.utcnow():%Y-%m-%d %H:%M:%S} UTC", inline=True)
    if differences:
        max_length = 900
        truncated_diff = differences if len(differences) <= max_length else differences[:max_length - 20] + "\n...\n(Truncated)"
        embed.add_field(name="Detected Changes", value=f"```diff\n{truncated_diff}\n```", inline=False)
        file_id = save_differences_to_drive(differences, file_name=f"differences_{url.replace('/', '_')}.txt", folder_id="1Rq_xtYnHy-XQ9i6nGrbdm9dFLoOfkwgg")
        if file_id:
            embed.add_field(name="Full Changes (Google Drive)", value=f"[View Changes](https://drive.google.com/file/d/{file_id}/view)", inline=False)
        else:
            embed.add_field(name="Full Changes", value="Failed to upload differences to Google Drive.", inline=False)

    try:
        with open(screenshot_path, "rb") as file:
            discord_file = discord.File(file, filename="screenshot.png")
            embed.set_image(url="attachment://screenshot.png")
            channel = bot.get_channel(CHANNEL_ID)
            if channel:
                await channel.send(embed=embed, file=discord_file)
            else:
                logging.error(f"Channel with ID {CHANNEL_ID} not found.")
    except FileNotFoundError:
        logging.error(f"Screenshot file not found: {screenshot_path}")
    except Exception as e:
        logging.error(f"Error sending deface report: {e}")
        
        
async def check_domain(session, url):
    """Check a domain for defacement or phishing by comparing DOMs."""
    try:
        sanitized_url = sanitize_filename(url)
        new_dom = await fetch_html(session, url)
        if not new_dom:
            #logging.warning(f"Failed to fetch DOM for {url}")
            return

        old_dom = await load_dom(url)
        if old_dom:
            old_hashes = get_kgram_hashes(preprocess_text(old_dom), 15, 256)
            new_hashes = get_kgram_hashes(preprocess_text(str(new_dom).upper()), 15, 256)
            similarity = get_jaccard_similarity(old_hashes, new_hashes)
            
            if int(similarity) < 80:
                logging.warning(f"Potential phishing detected for {url} (Similarity: {similarity:.2f}%)")
                # logging.warning(f"No potential phishing detected for {url} (Similarity: 96.67%)")
                differences = get_dom_diff(old_dom, new_dom)
                screenshot_path = getScreenshot(url)
                if screenshot_path:
                    await send_deface_report(url, screenshot_path, differences)
                else:
                    logging.error("Failed to capture screenshot.")
            else:
                logging.info(f"No potential phishing for {url} with similarity {similarity:.2f}%")
                # logging.warning(f"No potential phishing detected for {url} (Similarity: 96.67%)")
        else:
            logging.info(f"No previous DOM found for {url}, saving as new.")
        
        await save_dom(url, new_dom)
    except Exception as e:
        logging.error(f"Error checking domain {url}: {e}")

async def notify_offline(url, before, after):
    embed = discord.Embed(
        title="❌ Status web changed❌",
        description=f"{url} has changed from {before} to {after}.",
        color=discord.Color.red(),
        timestamp=datetime.utcnow()
    )
    try:
        channel = bot.get_channel(CHANNEL_ID)
        if channel:
            await channel.send(embed=embed)
        else:
            logging.error(f"Channel with ID {CHANNEL_ID} not found.")
    except Exception as e:
        logging.error(f"Error sending deface report: {e}")


async def process_record(session, domain_path, record_file):
    """Process each domain record and check for changes."""
    try:
        record_path = os.path.join(domain_path, record_file)
        with open(record_path, 'r') as file:
            data = json.load(file)

        url = data.get("domain")
        if not url:
            return

        is_online = bool(await fetch_html(session, url))
        if data["is_online"] != is_online:
            await notify_offline(url, data["is_online"], is_online)
            logging.info(f"Status of {url} changed from {data['is_online']} to {is_online}")

        data["is_online"] = is_online
        data["last_checked"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        with open(record_path, 'w') as file:
            json.dump(data, file, indent=4)

        await check_domain(session, url)
    except Exception as e:
        logging.error(f"Error processing record {record_file}: {e}")


async def check_website_statuses(domain):
    """Check the statuses of all websites in the domain."""
    domain_path = RECORD_DIR
    if not os.path.exists(domain_path):
        logging.error(f"Domain record directory not found: {domain_path}")
        return

    async with aiohttp.ClientSession() as session:
        task = []
        for record_file in os.listdir(domain_path):
            if domain in record_file:
                task.append(process_record(session, domain_path, record_file))
        await asyncio.gather(*task)


async def scheduler():
    schedule.every(30).seconds.do(check_website_statuses, "192.168.233.120")
    while True:
        await schedule.run_pending()
        await asyncio.sleep(1)


async def main():
    asyncio.create_task(scheduler())
    await bot.start("")  # Replace with your bot token


if __name__ == "__main__":
    asyncio.run(main())
