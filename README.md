# VirusTotal Telegram Bot

This Telegram bot allows you to check files, URLs, domains, and IP addresses using the VirusTotal API.

<div align="center">
  <a href="https://github.com/arhkypGitProject" target="_blank">
    <img src="https://img.shields.io/static/v1?message=GitHub&logo=github&label=&color=181717&logoColor=white&style=for-the-badge" height="25" />
  </a>
</div>

<div align="center">
  <img src="https://visitor-badge.laobi.icu/badge?page_id=arhkypGitProject.VirusTotal-Cheker-Bot-Telegram" />
</div>

## Project Structure

```
├── main.py                    # Main bot startup file
├── assets/                    # Helper modules
│   ├── commands.py           # Command and callback handlers
│   ├── cheker.py             # Functions for working with VirusTotal API
│   ├── dialog.py             # FSM (Finite State Machine) states
│   └── config.py             # Configuration data (tokens)
```

## Installation and Setup

### 1. Clone the Repository
```bash
git clone https://github.com/arhkypGitProject/VirusTotal-Cheker-Bot-Telegram.git
cd VirusTotal-Cheker-Bot-Telegram
```

### 2. Create Virtual Environment (Recommended)
```bash
python -m venv venv

# For Linux/Mac:
source venv/bin/activate

# For Windows:
venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install aiogram requests
```

### 4. Configuration Setup
Edit the `assets/config.py` file:

```python
TOKEN = 'YOUR_TELEGRAM_BOT_TOKEN'
API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'
```

**Where to get tokens:**
- **Telegram Bot Token**: Get it from [@BotFather](https://t.me/BotFather)
- **VirusTotal API Key**: Register on [VirusTotal](https://www.virustotal.com/) and get your API key from the dashboard

### 5. Create Required Folders
The bot will automatically create a `downloads` folder for temporary file storage on first run.

## Running the Bot

```bash
python main.py
```

Once running, the bot will be ready to use. Send the `/start` command in Telegram to begin.

## VirusTotal API Integration

### Supported Functions:

#### 1. **IP Addresses** (`ip_checker`)
- Check IP address reputation
- Get ASN, country, and owner information
- Last analysis statistics

#### 2. **URL Addresses** (`url_cheker`)
- Submit URLs for scanning
- Get analysis ID for tracking

#### 3. **Domains** (`domain_checker`)
- Domain reputation check
- Registrar information
- Voting statistics

#### 4. **Files** (`send_file_to_virustotal`)
- Upload files up to 650MB (VirusTotal limit)
- File analysis with multiple antivirus engines

#### 5. **Analysis Reports** (`analysis_report`)
- Get results by analysis ID
- Check scanning status
- View detection statistics

## Bot Features

### Main Menu Commands:
- `/start` - Display main menu with all options

### Available Checks:
1. **IP Scan** - Check IP address reputation
2. **File Check** - Upload and scan files
3. **URL Check** - Analyze suspicious URLs
4. **Domain Check** - Verify domain reputation
5. **URL/File Analysis** - Check existing analysis results using ID

### Technical Implementation:

#### FSM (Finite State Machine)
The bot uses aiogram's FSM for managing user states:
- `IPScan.waiting_for_ip`
- `URLScan.waiting_for_url`
- `DOMAINScan.waiting_for_domain`
- `FILEScan.waiting_for_file`
- `URLandFILEScan.waiting_for_id`

#### Async Operations
- All VirusTotal API calls are wrapped in `asyncio.to_thread()` to prevent blocking
- File downloads use async bot methods
- Temporary files are automatically cleaned up

#### Error Handling
- Comprehensive try-except blocks
- User-friendly error messages
- State clearing on errors

## API Rate Limits
- VirusTotal API has rate limits based on your subscription
- Free tier: 4 requests/minute, 500 requests/day
- Consider implementing delays for high-volume usage

## Security Notes
- This bot is for informational purposes only
- Not a replacement for antivirus software
- Files are deleted immediately after analysis
- API keys should be kept secure

## Customization
You can modify:
- Response formats in `commands.py`
- API endpoints in `cheker.py`
- Menu structure and buttons
- Logging configuration in `main.py`

## Troubleshooting

### Common Issues:
1. **API Key Errors**: Ensure your VirusTotal API key is valid
2. **File Size Limits**: VirusTotal has 650MB file limit
3. **Rate Limiting**: Implement delays if hitting API limits
4. **State Issues**: Use `/start` to reset bot state if needed

## Dependencies
- `aiogram==3.x` - Telegram Bot Framework
- `requests==2.3x` - HTTP library for API calls

## Disclaimer
This bot uses VirusTotal's public API. All scanning is performed by VirusTotal, not locally. Results are for informational purposes only. Always use multiple security solutions for comprehensive protection.

## Support
For issues or questions:
1. Check the VirusTotal API documentation
2. Review aiogram framework documentation
3. Examine error logs for specific issues

## Future Improvements
Potential enhancements:
- Add caching for frequently checked items
- Implement queue system for file uploads
- Add support for more VirusTotal endpoints
- Create admin panel for monitoring
- Add multilingual support
- Implement user statistics and analytics
