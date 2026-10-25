# 🛡️ ShieldAI
### See the Risk Before the Workflow Runs

ShieldAI is an AI-assisted URL security scanner that identifies potentially suspicious URL patterns and uses Google's Gemma model to explain potential risks in simple language.

## 🚨 Problem

Unsafe URLs and server-side request forgery (SSRF) risks can affect applications that process URLs from users or workflow configurations. Simple text-based checks may miss unusual URL representations or fail to account for how hostnames resolve.

## 💡 Solution

ShieldAI combines URL pattern checks with AI-generated explanations to help users understand potential security concerns before a workflow runs.

## ✨ Features

- URL scanning and risk assessment
- Detection of selected suspicious URL patterns
- AI-assisted explanations powered by Google Gemma
- Scan history and dashboard
- Suggested safer next steps
- Web-based interface built with Streamlit

## 🧰 Tech Stack

- Python
- Streamlit
- Google Gen AI SDK
- Google Gemma model

## ▶️ Run Locally

1. Clone this repository:

   ```bash
   git clone https://github.com/bindusri001/shieldAI.git
   cd shieldAI
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Create `.streamlit/secrets.toml` and add your Google AI Studio API key:

   ```toml
   GOOGLE_API_KEY = "YOUR_API_KEY_HERE"
   ```

4. Start the application:

   ```bash
   streamlit run app.py
   ```

## 🔐 Security Notes

ShieldAI is a defensive prototype for awareness and preliminary URL risk assessment. It does not guarantee that a URL is safe.

Production-grade SSRF protection may require DNS resolution, validation of resolved IP addresses, redirect checks, and protections against DNS rebinding at connection time.

Never commit API keys, passwords, or other secrets to GitHub.

## ⚠️ Disclaimer

ShieldAI is an educational security tool. Its results are advisory and should not replace comprehensive security validation.

## 👩‍💻 Author

**Bindu Sri**

GitHub: https://github.com/bindusri001
