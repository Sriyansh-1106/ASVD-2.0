#!/usr/bin/env python3
"""ASVD Demo - Synthetic Cyber-Scam Conversation Generator.

Generates a reproducible dataset of synthetic scam and safe conversations
for training the ASVD detection system. Indian context with English,
Hindi, and Hinglish conversations.

Usage:
    python data/generate_dataset.py
    python data/generate_dataset.py --stats

Output:
    data/synthetic_cyber_calls.csv
    data/synthetic_cyber_calls.json
    data/processed/train.csv
    data/processed/val.csv
    data/processed/test.csv
"""

import argparse
import os
import random
import sys


# Fix Windows encoding
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

# ====================================================================
# CONFIG
# ====================================================================

RANDOM_SEED = 42
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_CSV = os.path.join(SCRIPT_DIR, "synthetic_cyber_calls.csv")
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "synthetic_cyber_calls.json")
PROCESSED_DIR = os.path.join(SCRIPT_DIR, "processed")

# Target: ~4000 samples (2500 scam + 1500 safe)
SCAM_PER_CATEGORY = 167   # 167 x 15 = 2505
SAFE_PER_CATEGORY = 215   # 215 x 7 = 1505


# ====================================================================
# SCAM TEMPLATES - 15 categories, Indian context, English/Hinglish
# ====================================================================

SCAM_DATA = {
    "Family Impersonation": {
        "templates": [
            "Bhaiya, mujhe bahut zaroorat hai. Mera accident ho gaya hai. Please {amount} bhej do turant. Kisi ko mat batana.",
            "It's me, your {relation}. I had an accident and I need Rs {amount} urgently. Please transfer now. Don't tell anyone.",
            "Mummy ko mat batana, mera phone kho gaya. Main {place} mein phasa hoon. {amount} chahiye abhi. Please jaldi karo.",
            "Bhai, main hospital mein hoon. {amount} chahiye treatment ke liye. Turant bhej do UPI pe. Baad mein explain karunga.",
            "Please listen, I am your {relation}. I {problem} and need Rs {amount} immediately. Send to {phone}. Don't contact anyone.",
            "Meri bohot buri situation hai. Main {place} mein hoon, {problem}. {amount} de do please, kisi ko mat batana.",
            "Help me please. I am your {relation}. I {problem}. Send {amount} to this account urgently. I'll explain later.",
            "Jaldi karo please, {relation} bol raha hoon. {problem}. Mujhe {amount} chahiye abhi ke abhi. Papa ko mat bolna.",
            "Beta, mujhe pareshani mein hoon. {problem}. {amount} bhej do UPI se {phone} pe. Kisi ko pata mat chalne dena.",
            "I am stuck in {place}. This is your {relation}. Need {amount} right now. Please hurry, don't tell the family.",
        ],
        "vars": {
            "relation": ["brother", "bhai", "sister", "didi", "cousin", "beta", "bhaiya", "nephew"],
            "problem": ["had an accident", "got arrested", "am in hospital", "lost my wallet", "police ne pakda", "hospital mein hoon", "paisa chori ho gaya"],
            "amount": ["10,000", "20,000", "25,000", "40,000", "50,000", "75,000", "1,00,000"],
            "place": ["Delhi", "Mumbai", "Lucknow", "highway pe", "station pe", "dusre sheher mein"],
            "phone": ["9876543210", "8765432109", "7654321098", "9988776655"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 1, "secrecy_request": 1,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 0},
        "threat_level": "HIGH",
        "action": "Verify the caller through an independent communication channel before transferring money.",
    },

    "Kidnapping & Extortion Threat": {
        "templates": [
            "Maine tumhare {victim} ko kidnap kar liya hai. Mujhe Rs {amount} ki jarurat hai urgent chahiye warna bahut marunga. Police ko mat batana.",
            "Bhai mujhe Rs {amount} ki jarurat hai argent chahiye warna bahut marunga. Maine tumhare {victim} ko kidnap kar liya hai.",
            "Your {victim} is with us. Transfer Rs {amount} immediately to {phone} or we will kill him. Do not inform the police.",
            "Tumhara {victim} mere kabze mein hai. Agar zinda dekhna chahte ho toh turant Rs {amount} bhej do. Koi chalaaki mat karna.",
            "Maine tumhare {victim} ko uthwa liya hai. {amount} firauti chahiye aaj hi, warna jaan se maar dunga.",
            "Listen carefully, we have kidnapped your {victim}. Send {amount} right now or face the consequences. Keep this secret.",
            "Tumhare {victim} ki jaan khatre mein hai. {amount} transfer karo abhi ke abhi warna laash milegi. Kisi ko mat bolna.",
            "Maine kidnap kar liya hai tumhare {victim} ko. Urgent Rs {amount} chahiye. Police ke paas gaye toh jaan se haath dho baithoge.",
        ],
        "vars": {
            "victim": ["bete", "beti", "bacche", "bhai", "family member", "son", "daughter", "child"],
            "amount": ["50,000", "1,00,000", "2,00,000", "5,00,000", "10,00,000", "500000", "200000"],
            "phone": ["9876543210", "8765432109", "7654321098", "9988776655"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 1, "secrecy_request": 1,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 1},
        "threat_level": "CRITICAL",
        "action": "Do not transfer money. Immediately report the extortion/kidnapping threat to the local Police and Cyber Crime helpline 1930.",
    },

    "Friend Impersonation": {
        "templates": [
            "Yaar, main {name} bol raha hoon. {problem}. Rs {amount} chahiye urgently. Baad mein lautaunga. Please group mein mat bolna.",
            "Bro, it's {name}. I {problem}. Can you send Rs {amount} to {phone}? I'll pay back. Don't tell anyone.",
            "Hey, {name} here. {problem}. Need Rs {amount} right now. Please help. I'll explain later.",
            "Dost, meri help kar. {name} bol raha hoon. {problem}. {amount} chahiye. Kisi ko mat bata.",
            "Listen, this is {name}. I {problem} and I am desperate. Send Rs {amount} to UPI {phone}. Keep it private.",
            "Yaar please, {name} hoon. {problem}. Bahut zaroorat hai Rs {amount} ki. Turant bhej de. Group mein mat bol.",
            "Bhai {name} bol raha hoon. Meri {problem}. Kya tu Rs {amount} bhej sakta hai? Wapas kar dunga. Secret rakh.",
            "It's me {name}. Something bad happened, {problem}. I need {amount} right away. Please don't mention to others.",
        ],
        "vars": {
            "name": ["Rahul", "Priya", "Amit", "Sneha", "Vikram", "Ankita", "Rohit", "Pooja", "Arjun", "Neha"],
            "problem": ["lost my wallet at station", "phone chori ho gaya", "am stuck without money", "had a bike accident",
                       "need emergency cash", "hospital ka bill bharna hai", "missed my train", "wallet gir gaya"],
            "amount": ["5,000", "8,000", "10,000", "15,000", "20,000", "25,000"],
            "phone": ["9123456780", "8234567890", "7345678901", "9876501234"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 1, "secrecy_request": 1,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 0},
        "threat_level": "HIGH",
        "action": "Contact the person directly using a known phone number to verify their identity.",
    },

    "Police Impersonation": {
        "templates": [
            "Main {rank} bol raha hoon Cyber Crime se. Aapke Aadhaar pe {case}. Rs {amount} settlement do warna arrest hoga.",
            "This is {rank} from Cyber Crime Department. {case}. Pay Rs {amount} immediately or face arrest. Do not disconnect.",
            "Aapke khilaf {case}. Main {rank} hoon. Rs {amount} jama karo verification account mein. Kisi lawyer ko mat bulao.",
            "I am {rank}. A warrant has been issued. {case}. Transfer Rs {amount} as security deposit to close the case.",
            "Dhyan se suniye, {rank} bol raha hoon. {case}. 2 ghante mein Rs {amount} jama nahi kiya toh ghar pe police aayegi.",
            "Attention! {rank} speaking. {case}. Court order ke mutabik Rs {amount} jama karna hoga. Non-compliance means jail.",
            "Yeh police headquarters se call hai. {rank} bol raha hoon. {case}. Rs {amount} as case closure fee bhejiye aaj hi.",
            "This is a serious matter. I am {rank}. {case}. Immediately transfer Rs {amount} or officers will come to your house.",
        ],
        "vars": {
            "rank": ["Inspector Sharma", "Sub-Inspector", "Senior Inspector", "ACP sahab", "Cyber Cell Officer", "DCP office se"],
            "case": ["criminal complaint file hua hai", "aapka account money laundering mein involved hai",
                     "aapki identity fraud mein use hui hai", "IT Act ke under case registered hai",
                     "your bank account is linked to a terror funding case", "aapke phone number pe FIR hai"],
            "amount": ["50,000", "75,000", "1,00,000", "1,50,000", "2,00,000", "5,00,000"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 0, "secrecy_request": 1,
                       "authority_impersonation": 1, "otp_request": 0, "credential_request": 0, "threat_detected": 1},
        "threat_level": "CRITICAL",
        "action": "Hang up and contact the local police station directly. Real police never demand money over phone.",
    },

    "Government Impersonation": {
        "templates": [
            "Yeh {dept} se call hai. {scenario}. Rs {amount} fine bharo warna legal action hoga. 24 ghante ka time hai.",
            "This is {dept}. {scenario}. Pay Rs {amount} immediately to avoid prosecution. Do not discuss with anyone.",
            "Official notice from {dept}. {scenario}. Transfer Rs {amount} as compliance fee within 3 hours.",
            "Aapko {dept} se final notice mil raha hai. {scenario}. Rs {amount} jama karo aaj hi. Passport cancel hoga.",
            "I am calling from {dept}. {scenario}. Unless Rs {amount} is paid today, your accounts will be frozen.",
            "{dept} ki taraf se automated message. {scenario}. Rs {amount} settlement jama karein. Kal tak ka waqt hai.",
            "Urgent from {dept}: {scenario}. Rs {amount} verification fee bhejiye. Nahi toh asset seizure hoga.",
            "Yeh {dept} ka officer bol raha hai. {scenario}. Aapko Rs {amount} dena hoga nahi toh arrest warrant issue hoga.",
        ],
        "vars": {
            "dept": ["Income Tax Department", "TRAI", "Customs Department", "RBI", "Ministry of Finance", "Telecom Authority"],
            "scenario": ["aapke PAN card pe tax evasion flagged hai", "your Aadhaar is used in illegal activities",
                        "aapka mobile number 24 ghante mein disconnect hoga", "aapki tax return mein discrepancy hai",
                        "your bank accounts will be frozen", "aapke naam pe suspicious parcel hai"],
            "amount": ["25,000", "50,000", "1,00,000", "2,00,000", "3,00,000"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 0, "secrecy_request": 1,
                       "authority_impersonation": 1, "otp_request": 0, "credential_request": 0, "threat_detected": 1},
        "threat_level": "CRITICAL",
        "action": "No government agency demands payment over phone. Contact the department through official channels.",
    },

    "Bank Fraud": {
        "templates": [
            "Dear customer, {bank} se call hai. {scenario}. Account bachane ke liye abhi OTP batayein jo aapke phone pe aaya hai.",
            "{bank} fraud prevention team. {scenario}. Please share the 6-digit OTP sent to your number for verification.",
            "{bank} se bol rahe hain. {scenario}. Security ke liye apna OTP aur card ke last 4 digits batayein.",
            "Alert from {bank}. {scenario}. Apna internet banking password share karein verification ke liye. Yeh urgent hai.",
            "Yeh {bank} security department hai. {scenario}. OTP batayein 10 minute mein warna account permanently lock ho jayega.",
            "{bank} se important call. {scenario}. Card ke peeche ka CVV aur OTP batayein to block suspicious activity.",
            "Namaste, {bank} ka fraud team bol raha hai. {scenario}. Turant OTP share karein account secure karne ke liye.",
            "This is {bank} calling. {scenario}. We need your OTP and card details immediately to prevent unauthorized access.",
        ],
        "vars": {
            "bank": ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "PNB", "Bank of Baroda", "Kotak Bank"],
            "scenario": ["aapke account se Rs 45,000 ka suspicious transaction hua hai", "your debit card is compromised",
                        "aapka account block hone wala hai", "unauthorized login detected in net banking",
                        "aapke card se online payment attempt hua hai", "your account is flagged for unusual activity"],
        },
        "indicators": {"urgency": 1, "financial_request": 0, "emotional_manipulation": 0, "secrecy_request": 0,
                       "authority_impersonation": 1, "otp_request": 1, "credential_request": 1, "threat_detected": 1},
        "threat_level": "CRITICAL",
        "action": "Never share OTP, PIN, or passwords. Call your bank's official helpline number printed on your card.",
    },

    "OTP Scam": {
        "templates": [
            "Hello, {caller} bol raha hoon. {pretext}. Jo 6-digit code aaya hai wo bata dijiye please. Bahut urgent hai.",
            "{caller} se call hai. {pretext}. Aapke number pe ek verification code aaya hoga. Please share karein.",
            "Namaste, main {caller} hoon. {pretext}. Aapke {platform} pe jo OTP aaya hai wo bata dijiye. 5 minute mein expire ho jayega.",
            "Sir/Madam, {caller} here from {platform}. {pretext}. Please tell me the OTP sent to your phone.",
            "Main {caller} bol raha hoon. Mera OTP galat number pe chala gaya. {pretext}. Please wo code bata do.",
            "Hello ji, {caller} hoon. {pretext}. {platform} ka OTP share kar dijiye jaldi, warna process cancel ho jayega.",
            "{caller} bol raha hoon {platform} se. {pretext}. Please OTP batayein turant. Call recorded hai.",
            "Yeh {caller} hai. {pretext}. Aapke {platform} account ke liye OTP aaya hoga. Jaldi batayein please.",
            "Main {caller} hoon. Galti se aapke number pe {platform} ka OTP aa gaya. Please bata dijiye.",
            "{caller} speaking. {pretext}. OTP share karna zaroori hai warna {platform} account block ho jayega.",
        ],
        "vars": {
            "pretext": ["KYC update ho raha hai", "refund process ho raha hai", "reward points expire ho rahe hain",
                       "aapka mobile verify karna hai", "your account is being updated", "lucky draw mein aap jeete hain",
                       "aapki delivery ke liye verification chahiye", "payment gateway se verification hai",
                       "cashback claim karna hai", "account reactivation ke liye", "subscription renew ho raha hai"],
            "caller": ["customer care", "executive", "verification officer", "support team", "helpdesk",
                      "technical support", "service team", "account manager"],
            "platform": ["Paytm", "PhonePe", "Google Pay", "Amazon", "Flipkart", "bank",
                        "UPI", "WhatsApp Pay", "BHIM", "Swiggy", "Zomato"],
        },
        "indicators": {"urgency": 1, "financial_request": 0, "emotional_manipulation": 0, "secrecy_request": 0,
                       "authority_impersonation": 0, "otp_request": 1, "credential_request": 0, "threat_detected": 0},
        "threat_level": "HIGH",
        "action": "Never share OTP with anyone. OTPs are for your personal transactions only.",
    },

    "PIN/Credential Scam": {
        "templates": [
            "{bank} ka technical team bol raha hai. {pretext}. ATM PIN aur net banking password share karein.",
            "Dear customer, {bank} se hai. {pretext}. Apna debit card number, CVV, aur expiry date batayein abhi.",
            "{bank} se verification call. {pretext}. Internet banking user ID aur password dijiye.",
            "{bank} ka {caller} bol raha hai. {pretext}. Card ke 16-digit number, CVV, aur PIN batayein.",
            "{caller} from {bank}. {pretext}. UPI PIN aur Aadhaar ke last 4 digits share karein.",
            "Yeh {bank} ka {caller} hai. {pretext}. Card number aur CVV chahiye security update ke liye.",
            "We are {caller} from {bank}. {pretext}. Share your net banking credentials for verification.",
            "{bank} se {caller} bol raha hai. {pretext}. Turant ATM PIN batayein warna card block ho jayega.",
            "Namaste, {bank} ka {caller} hoon. {pretext}. Apna password aur card details share karein.",
            "{caller} here from {bank} IT department. {pretext}. We need your login credentials immediately.",
        ],
        "vars": {
            "pretext": ["net banking upgrade ho raha hai", "aapke account ki re-verification zaruri hai",
                       "unknown device se login detect hua", "card renewal ke liye", "system migration chal raha hai",
                       "your card has been flagged", "security audit ke liye", "KYC update mandatory hai",
                       "account mein technical error hai", "new RBI guidelines ke according update chahiye"],
            "bank": ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "PNB", "Kotak Bank", "Yes Bank", "IndusInd Bank"],
            "caller": ["technical team", "security officer", "IT head", "verification officer", "system admin",
                      "senior executive", "compliance team", "fraud prevention officer"],
        },
        "indicators": {"urgency": 1, "financial_request": 0, "emotional_manipulation": 0, "secrecy_request": 0,
                       "authority_impersonation": 1, "otp_request": 0, "credential_request": 1, "threat_detected": 0},
        "threat_level": "HIGH",
        "action": "Banks never ask for PIN, CVV, or passwords over phone. Never share these with anyone.",
    },

    "Investment Scam": {
        "templates": [
            "Congratulations! {scheme} mein invest karein sirf Rs {amount}. Guaranteed 300% return 3 mahine mein. Aaj hi join karein.",
            "Hello, {scheme} ka exclusive offer hai. Rs {amount} lagayein, paise double honge 45 din mein. Limited seats.",
            "{scheme} abhi open hai. Minimum Rs {amount}. Returns guaranteed. Register karein 2 ghante mein. Kisi ko mat batana.",
            "Sir/Madam, {scheme} mein invest karein Rs {amount}. 100% safe aur legal. Passive income shuru karein aaj se.",
            "Special offer: {scheme}. Rs {amount} invest karein aur weekly payout paayen. Yeh offer sirf aaj ke liye hai.",
            "Dear investor, {scheme} se record profits aa rahe hain. Rs {amount} transfer karein aaj. First payout ek hafte mein.",
            "{scheme} se log crorepati ban rahe hain. Rs {amount} se shuru karein. No risk. Money back guarantee. Act now.",
            "Aapko select kiya gaya hai {scheme} ke liye. Rs {amount} lagayein, 500% return milega. Offer expires today.",
        ],
        "vars": {
            "scheme": ["guaranteed stock market plan", "crypto trading opportunity", "mutual fund with 40% returns",
                      "exclusive real estate deal", "government-backed scheme", "forex trading with zero risk",
                      "AI-powered trading bot", "private equity fund"],
            "amount": ["10,000", "25,000", "50,000", "1,00,000", "2,00,000"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 1, "secrecy_request": 0,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 0},
        "threat_level": "HIGH",
        "action": "Verify investments through SEBI registered channels. No legitimate investment guarantees fixed returns.",
    },

    "Job Scam": {
        "templates": [
            "Congratulations! {job} ke liye select hue hain. Salary Rs 25,000-50,000 per month. Registration fee Rs {amount} do.",
            "Hello, aapka resume dekha. {job} ka opening hai. Rs {amount} training kit fee do. Start earning from tomorrow.",
            "{job} opportunity - work from home. Daily Rs 1,000-5,000 kamayein. Registration fee sirf Rs {amount}. Limited seats.",
            "Job Alert: {job} position open. No experience needed. Rs 30,000+ monthly. Processing fee Rs {amount}. Pay via UPI.",
            "Kya aap extra income chahte hain? {job} mein opportunity hai. Registration Rs {amount}. Students aur housewives welcome.",
            "Selected for {job}! Ghar baithe kamayein. Fee Rs {amount} UPI pe bhejein. Login credentials mil jayenge turant.",
            "Dear candidate, {job} vacancy available. Pay Rs {amount} for onboarding. Start earning immediately. Hurry up.",
            "Aapke liye {job} ka offer hai. Monthly Rs 40,000+. One-time fee Rs {amount}. Pay now and start today.",
        ],
        "vars": {
            "job": ["data entry from home", "social media marketing", "online survey work", "part-time typing",
                   "Amazon review job", "YouTube video liking", "Instagram followers badhane ka kaam", "copy paste job"],
            "amount": ["499", "999", "1,499", "2,500", "4,999", "7,500"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 0, "secrecy_request": 0,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 0},
        "threat_level": "MEDIUM",
        "action": "Legitimate employers never ask for money upfront. Verify through the company's official website.",
    },

    "Loan Scam": {
        "templates": [
            "Instant {loan_type} Rs {loan_amt} at 2% interest. No documents. Pre-approved. Processing fee Rs {amount}. Aaj hi valid.",
            "Aapka {loan_type} Rs {loan_amt} pre-approved hai. Rs {amount} insurance aur processing fee bhejein. Loan 24 ghante mein.",
            "Dear customer, {loan_type} Rs {loan_amt} sanctioned. Rs {amount} GST aur fee jama karein. Amount aaj credit hoga.",
            "{loan_type} Rs {loan_amt} bina collateral ke. Rs {amount} security deposit bhejein. Amount aaj hi milega.",
            "Urgent: Aapka {loan_type} application Rs {loan_amt} approved. Rs {amount} verification charges do. Delay = cancellation.",
            "Congratulations! {loan_type} Rs {loan_amt} ready. Sirf Rs {amount} processing fee. Zero documentation. Apply now.",
            "{loan_type} offer: Rs {loan_amt} at lowest interest. Rs {amount} one-time fee. Disbursement within 2 hours.",
            "Pre-approved {loan_type} Rs {loan_amt}. Rs {amount} jama karein turant. Offer sirf aaj ke liye hai.",
        ],
        "vars": {
            "loan_type": ["personal loan", "business loan", "instant loan", "education loan", "home loan", "emergency loan"],
            "amount": ["2,000", "5,000", "8,000", "12,000", "15,000"],
            "loan_amt": ["1,00,000", "2,00,000", "5,00,000", "10,00,000", "20,00,000"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 0, "secrecy_request": 0,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 0},
        "threat_level": "MEDIUM",
        "action": "No genuine bank charges processing fees before loan disbursement. Verify through official channels.",
    },

    "Extortion": {
        "templates": [
            "Hum jaante hain tum kaun ho. {threat}. 24 ghante mein Rs {amount} bhejo warna sab contacts ko bhej denge.",
            "Listen carefully. {threat}. Pay Rs {amount} within 12 hours or we publish everything online.",
            "Final warning. {threat}. Rs {amount} transfer karo. Police ko bulaya toh aur bura hoga. Hum untraceable hain.",
            "Yeh tumhari last chance hai. {threat}. Rs {amount} do warna social media pe sab expose karenge. 6 ghante hain.",
            "{threat}. Rs {amount} bhejo nahi toh publicly release karenge. 48 ghante ka time hai. Hum dekh rahe hain.",
            "Tum jaante ho kya hoga agar {threat}. Rs {amount} de do aur sab khatam. Warna consequences face karo.",
            "We have everything. {threat}. Transfer Rs {amount} via UPI or NEFT. No police. No negotiation.",
            "{threat}. Tumhare employer ko bhi bhejenge. Rs {amount} jama karo aaj raat tak. Final hai yeh.",
        ],
        "vars": {
            "threat": ["tumhari private photos aur videos hain hamare paas", "we recorded your screen activity",
                      "tumhari browsing history hai hamare paas", "we hacked your webcam", "tumhare private messages hain",
                      "compromising information hai tumhari", "tumhare social media accounts hack kiye hain"],
            "amount": ["50,000", "1,00,000", "2,00,000", "5,00,000"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 1, "secrecy_request": 1,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 1},
        "threat_level": "CRITICAL",
        "action": "Do not pay. Report to Cyber Crime helpline 1930 and local police station immediately.",
    },

    "Blackmail": {
        "templates": [
            "Mere paas {leverage} hai. Agar spouse aur colleagues ko nahi dikhana toh Rs {amount} bhejo. Kal subah tak.",
            "We have obtained {leverage}. Sab contacts ko bhej denge agar Rs {amount} nahi mile. Serious hain hum.",
            "Pay attention. {leverage} hai hamare paas aur jaante hain kahan kaam karte ho. Rs {amount} do. Warna share.",
            "Yeh mazaak nahi hai. {leverage} hai mere paas. Rs {amount} Google Pay ya PhonePe se bhejo 24 ghante mein.",
            "I have {leverage}. Rs {amount} doge toh permanently delete. Ignore karoge toh reputation khatam.",
            "{leverage} hai mere paas. Tumhare family ko dikhaunga agar Rs {amount} nahi mile 48 ghante mein.",
            "Tumhari {leverage} public karni hai ya Rs {amount} doge? Choice tumhari hai. Time kam hai.",
            "We possess {leverage}. Pay Rs {amount} or face public humiliation. No second chances.",
        ],
        "vars": {
            "leverage": ["chat screenshots", "dating app profile", "deleted social media posts",
                        "private messages", "video call recordings", "personal photos",
                        "browsing history", "private conversations"],
            "amount": ["25,000", "50,000", "1,00,000", "3,00,000"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 1, "secrecy_request": 1,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 1},
        "threat_level": "CRITICAL",
        "action": "Do not pay. Report to Cyber Crime helpline 1930 and local police station immediately.",
    },

    "Emergency Money Scam": {
        "templates": [
            "Hello, {relation} ka {emergency} hua hai. Unhone kaha aapko call karein. Rs {amount} chahiye turant treatment ke liye.",
            "Yeh hospital se call hai. {relation} ko {emergency} ke baad laye hain. Doctor ko Rs {amount} chahiye. Jaldi bhejiye.",
            "Please mat ghabraiye. {relation} ka {emergency} hua hai. Unke colleague bol rahe hain. Rs {amount} bhejiye. Jaldi.",
            "Urgent: {relation} danger mein hai. {emergency} situation hai. Rs {amount} turant transfer karein {phone} pe.",
            "Yeh serious hai. {relation} ka {emergency} hua hai. Rs {amount} chahiye ek ghante mein. Family ko mat batao abhi.",
            "{relation} ka {emergency} ho gaya. Hospital wale Rs {amount} maang rahe hain. Please jaldi bhejein.",
            "Main {relation} ke saath hoon. Unka {emergency} hua hai. Rs {amount} chahiye turant. Please help karein.",
            "Emergency call: {relation} ko {emergency} hua. Rs {amount} immediately chahiye. Hum hospital mein hain.",
        ],
        "vars": {
            "relation": ["aapke papa", "aapki mummy", "your father", "your mother", "aapke husband", "your wife",
                        "aapka beta", "your child", "aapke dada ji", "a close relative"],
            "emergency": ["medical emergency", "road accident", "heart attack", "ghar mein aag lag gayi",
                         "bahut bura accident", "serious injury", "surgery zaruri hai"],
            "amount": ["20,000", "35,000", "50,000", "75,000", "1,00,000"],
            "phone": ["9191919191", "8282828282", "7373737373"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 1, "secrecy_request": 1,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 0},
        "threat_level": "HIGH",
        "action": "Verify the emergency by contacting the person or hospital directly through known numbers.",
    },

    "Fake Parcel/Customs Scam": {
        "templates": [
            "Customs Department se call hai. {item} aapke naam aur Aadhaar pe registered hai. Rs {amount} clearance fee do warna case.",
            "Courier company se bol rahe hain. {item} border pe roka gaya. Aapki ID thi. Rs {amount} customs duty do.",
            "Attention: {item} airport pe seize hua hai. Aapka naam linked hai. Rs {amount} transfer karein 4 ghante mein.",
            "Final notice. {item} authorities ke paas hai. Rs {amount} verification fee do warna police aayegi aaj.",
            "Warning: {item} under investigation hai. Aapka Aadhaar linked hai. Rs {amount} do warna passport cancel.",
            "{item} customs ne pakda hai. Aapke naam pe hai. Rs {amount} jama karein clearance ke liye. Urgent hai.",
            "Yeh customs department se official call hai. {item} aapke address pe register hai. Rs {amount} fine bharo.",
            "This is courier service. {item} has been intercepted. Pay Rs {amount} or criminal charges will be filed.",
        ],
        "vars": {
            "item": ["illegal drugs wala parcel", "fake currency ka package", "contraband shipment",
                    "banned substances wala courier", "suspicious contents wala package", "international illegal parcel"],
            "amount": ["15,000", "25,000", "50,000", "1,00,000"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 0, "secrecy_request": 0,
                       "authority_impersonation": 1, "otp_request": 0, "credential_request": 0, "threat_detected": 1},
        "threat_level": "CRITICAL",
        "action": "No customs or courier service demands payment over phone. Verify through official channels.",
    },

    "Financial Manipulation": {
        "templates": [
            "Good news! {tactic}. Claim karne ke liye Rs {amount} processing fee do. Full amount 48 ghante mein milega.",
            "Congratulations! {tactic}. Rs {amount} verification charges do aur amount turant credit hoga. Aaj hi valid.",
            "Hello, {tactic}. Aap eligible hain. Rs {amount} service charges do. One-time fee hai.",
            "Dear customer, {tactic}. Rs {amount} nominal fee do funds release karne ke liye. Jaldi karo, expire hoga.",
            "{tactic}. Lekin Rs {amount} government processing charges pehle dene honge. Pay now.",
            "Aapke account mein {tactic}. Rs {amount} de dijiye processing ke liye. Turant amount aa jayega.",
            "Exciting offer: {tactic}. Sirf Rs {amount} fee mein claim karein. Offer aaj raat tak hai.",
            "{tactic}. Rs {amount} pay karein aur paise le jayein. Yeh genuine government scheme hai.",
        ],
        "vars": {
            "tactic": ["Rs 50,000 ka tax refund eligible hai aap", "unclaimed insurance payout hai aapka",
                      "government subsidy ke liye select hue hain", "Rs 10,000 cashback reward pending hai",
                      "PPF account mein bonus interest claim karna hai", "LIC ka bonus mature hua hai",
                      "income tax refund pending hai aapka", "PM Yojana ke under Rs 1 lakh milega"],
            "amount": ["1,000", "2,000", "3,000", "5,000", "7,500"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 1, "secrecy_request": 0,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 0},
        "threat_level": "MEDIUM",
        "action": "No legitimate organization asks for fees to release refunds. Verify through official channels.",
    },
}


# ====================================================================
# SAFE TEMPLATES - 7 categories, Indian context
# ====================================================================

SAFE_DATA = {
    "Family Conversation": [
        "Hi mummy, main office pahunch gayi. Traffic bahut tha aaj. 7 baje tak aa jaungi ghar.",
        "Doodh aur bread le aana ghar aate waqt. Papa ki dawai bhi leni hai pharmacy se.",
        "Happy birthday! Maine cake order kiya hai. 5 baje tak aa jayega. Poora family aa raha hai raat ko.",
        "Uncle se baat hui. Cousin ki shaadi December mein fix hui hai. Train tickets book karni hain.",
        "Bhai ko hospital le ja rahi hoon regular checkup ke liye. Dopahar ke baad nikalenge.",
        "Maid ke account mein 5,000 transfer kar dena. Usne salary maangi hai, month end hai.",
        "School mein hoon. Teacher milna chahti hain bacche ki progress ke baare mein. Routine meeting hai.",
        "Didi ka flight 2 ghante late hai. Airport ke liye 9 baje nikalna chahiye ab.",
        "Grocery ke liye 2,000 bhej do. Main supermarket mein hoon, wallet ghar bhool gayi.",
        "Daadi ji aaj better feel kar rahi hain. Doctor ne kaha kal ghar aa sakti hain.",
        "Salary credit ho gayi aaj. Joint account mein transfer karna hai toh bata do kitna.",
        "Mummy, hostel pahunch gayi main. Chinta mat karo. Warden bahut strict hai safety ke baare mein.",
        "Papa, school ki fee next week due hai. Rs 15,000 hai is semester. School account mein bhej dena.",
        "Plumber kal subah aayega kitchen ka tap theek karne. Koi ghar pe hona chahiye 10-12 ke beech.",
        "Sunday lunch ke liye restaurant book kiya hai. Naya wala hai mall ke paas. Poora family aa sakta hai.",
        "Beta ki parent-teacher meeting hai Friday ko. 3 baje jaana hai school. Tum aa sakte ho?",
        "Nani ke liye medicine order kiya hai online. Kal tak aa jayegi. Unka BP normal hai ab.",
        "Ghar ka bijli ka bill aaya hai Rs 3,500. Online pay kar deti hoon aaj raat ko.",
        "Chhotu ka result aa gaya. Bahut achhe marks aaye hain. Party rakhte hain weekend pe.",
        "Mausam kharab hai aaj, jaldi ghar aa jaana. Barish shuru hone wali hai.",
    ],
    "Friend Conversation": [
        "Yaar, weekend pe free ho? Movie chalte hain. Naya action movie release hua hai.",
        "Bro, assignment submit kiya? Kal deadline hai. Mere do pages baaki hain abhi.",
        "Happy anniversary yaar! Dinner plan karte hain saath mein. Bahut din ho gaye milke.",
        "Naya gym join kiya hai ghar ke paas. Trainer bahut achha hai. Tu bhi try kar.",
        "Aaj ki lecture ke notes share kar do. Mujhe dentist ke liye early jaana pada.",
        "Next month road trip plan karte hain. Goa ya Pondicherry? Kya sochte ho?",
        "Promotion mil gayi! Weekend pe dinner treat karunga. Restaurant tum choose karo.",
        "Kal raat ka cricket match dekha? Kya incredible finish tha! Last over mein kya hua yaar!",
        "Laptop khareedna hai, budget Rs 60,000 hai. Koi suggestion hai?",
        "Woh restaurant yaad hai jahan gaye the? Naya menu aaya hai. Friday ko chalein?",
        "Vikram ko 3,000 diye the last week. Usne bola aaj return karega. Bas reminder hai.",
        "Saturday ko shifting mein help kar sakta hai? Naye apartment mein ja raha hoon.",
        "Concert ke tickets aaye hain! Rs 2,500 each. Do book karoon? Jaldi bata, sell ho jayenge.",
        "Driving test pass ho gaya! Teen attempts ke baad finally license mila. Ab car khareedni hai.",
        "Gym ke baad chai pi rahe hain kya? Woh tapri pe milte hain jo college ke paas hai.",
        "IPL ka naya season shuru hone wala hai. Fantasy team banate hain saath mein.",
        "Yaar mera phone ka screen toot gaya. Koi achhi repair shop pata hai tujhe?",
        "Birthday party ke liye venue suggest karo. Budget Rs 15,000 tak hai. 20 log honge.",
        "Kal ka exam kaisa gaya? Mera toh theek thak hua. Paper lamba tha bahut.",
        "Photography club join kiya hai. Weekend pe photowalk hai. Aana hai toh bata.",
    ],
    "Work Conversation": [
        "Good morning. Client meeting 3 PM reschedule ho gayi hai. Calendar update kar lena.",
        "Quarterly report bhej diya hai. Review karke feedback de dena end of day tak.",
        "Project deadline ek week extend hua hai. Next Friday tak submit karna hai ab.",
        "Testing server ke login credentials share kar do. Aaj kuch tests run karne hain.",
        "HR ne bola naya leave policy next month se lagegi. 5 extra casual leaves milenge.",
        "Kal work from home karunga. Subah plumber aa raha hai. Dopahar tak online aa jaunga.",
        "Team outing Saturday ko confirm hai. Adventure park ja rahe hain. Bus 8 AM nikalegi.",
        "Manager ne naye software license ka budget approve kiya. Purchase order process karunga aaj.",
        "Presentation file bhej do. Kal ki meeting se pehle kuch slides add karni hain.",
        "Office Wi-Fi password change hua hai. Naya password notice board pe hai reception ke paas.",
        "Friday tak timesheets submit kar do. Finance ko urgently chahiye monthly payroll ke liye.",
        "Kal half-day leave leni hai bank appointment ke liye. Subah ka kaam complete kar dunga.",
        "Server subah 30 minute down tha. IT team ne fix kar diya. Sab normal hai ab.",
        "Standup meeting 10 AM pe hai daily ab. Timing change hua hai, pehle 9:30 tha.",
        "New hire ka onboarding hai next week. Training material ready karni hai. Help karoge?",
        "Canteen mein naya menu aaya hai. Lunch pe chalein saath mein? Paneer tikka try karte hain.",
        "Appraisal cycle start hone wala hai. Self-assessment form fill kar lena December tak.",
        "AC kharab hai conference room ka. Facility team ko complaint kiya hai. Evening tak theek hoga.",
        "Client ne feedback bheja hai. Bahut khush hain project se. Good job team!",
        "Weekend pe deployment hai. Saturday raat ko 11 baje se start karenge. Tum available ho?",
    ],
    "Bank Enquiry": [
        "Hello, mujhe account balance jaanna hai. Account number 4523 mein end hota hai.",
        "Fixed deposit scheme ke baare mein message aaya tha. Interest rates bata dijiye.",
        "Bank se call aayi thi account statement ke baare mein. Branch se collect karna hai.",
        "Address update karna hai bank records mein. Online ho sakta hai ya branch jaana padega?",
        "Credit card ke liye apply karna hai. Kaunse documents chahiye aur kitna time lagega?",
        "Cheque book khatam ho gayi hai. Naya issue kar dijiye please. Next week tak chahiye.",
        "Beti ke liye savings account kholna hai. Abhi 18 saal ki hui hai. Kya schemes hain?",
        "Ghar ke paas ka ATM 3 din se band hai. Koi aur ATM nearby hai kya?",
        "Rs 10,000 per month recurring deposit set kiya tha. Confirm kar dijiye active hai ya nahi.",
        "Aadhaar link karna hai bank account se. Online procedure kya hai?",
        "Credit card statement mein ek charge nahi samajh aa raha. Investigate kar sakte hain?",
        "International fund transfer karna hai. SWIFT charges kitne hain?",
        "Fixed deposit mature ho gayi hai. Renew karni hai ya amount withdraw karna hai?",
        "Locker ke liye apply karna hai branch mein. Availability hai kya? Charges kitne hain?",
        "Net banking ka password reset karna hai. Branch jaana padega ya online ho jayega?",
        "Home loan ke liye pre-approved offer aaya hai. Details jaanni hain interest rate ki.",
        "Debit card expire hone wala hai. Naya kab milega? Automatic renewal hai kya?",
        "Mobile number update karna hai bank account mein. Kya process hai?",
        "Statement of account chahiye last 6 months ka. Email pe bhej sakte hain?",
        "PPF account ka balance check karna hai. Passbook update karwa sakta hoon kya?",
    ],
    "Shopping Conversation": [
        "Phone order kiya hai online, kal aayega. Delivery person call karega pehle.",
        "Friday se sale shuru hai. Sab 50% off hai. Shopping chalein office ke baad?",
        "Shirt return ki jo last week khareedt thi. Refund 5-7 business days mein aayega.",
        "Grocery store mein fresh vegetables hain kya check karo. Tamatar, pyaaz, aloo chahiye.",
        "Naya washing machine khareedda. Saturday subah installation scheduled hai.",
        "Laptop ki warranty next month expire ho rahi hai. Extended warranty leni chahiye?",
        "Store pe hoon. Refrigerator pe achha offer hai. Samsung loon ya LG? Budget Rs 30,000.",
        "Naye sofa ke Rs 15,000 diye. Delivery 2 weeks mein hogi. Quality achhi hai.",
        "Bacchon ke school supplies khareedne hain. Notebooks, pens, aur naya school bag.",
        "Amazon delivery person ne bola package deliver ho gaya. Door pe check karo.",
        "Swiggy se khana order kiya hai. 40 minutes mein aayega. Tumhare liye bhi order karoon?",
        "Myntra pe sale lagi hai. Kurta set khareedna hai. Budget Rs 2,000 hai. Suggest karo.",
        "Kirana wale ka hisaab karna hai. Rs 4,500 baaki hai. UPI se bhej deti hoon.",
        "Flipkart se AC order kiya hai. Installation free hai. Wednesday ko aayega.",
        "Sabzi mandi se taza sabzi layi hoon. Palak, methi, aur gaajar mili achhi waali.",
        "Diwali ki shopping start karni hai. Kapde aur gifts dono khareedne hain.",
        "Pharmacy se dawai le aao. Prescription photo bhej rahi hoon WhatsApp pe.",
        "BigBasket se monthly grocery order kar diya hai. Kal morning slot mein aayega.",
        "Bacche ke shoes tight ho gaye hain. Weekend pe naye khareedne jaana hai.",
        "Electronics store mein printer pe discount hai. Office ke liye chahiye tha. Rs 8,000 ka hai.",
    ],
    "Government Enquiry": [
        "Passport office gayi thi aaj. Renewal 15 working days mein hoga bole.",
        "Income tax return file karna hai deadline se pehle. Achha CA suggest karo.",
        "Railway station ke paas Aadhaar centre 9 AM se 5 PM tak khula hai. Kal jaungi.",
        "Driving license renew karwa liya. Smooth process tha. RTO mein ek ghanta laga.",
        "Property tax is quarter ka Rs 8,000 hai. Online pay kar dungi due date se pehle.",
        "Ration card ke liye apply kiya tha last month. Status shows under processing.",
        "Election ID card update camp community center mein hai is Saturday ko.",
        "PAN card aaya hai mail mein. Ab fixed deposit account khol sakti hoon.",
        "Water bill is mahine zyada aaya hai. Municipal office call karke verify karungi.",
        "Aadhaar-PAN linking online kar liya. Bahut easy tha. Bas details dalne the.",
        "Voter ID mein address change karwana hai. Online portal pe apply kar sakti hoon kya?",
        "Gas connection ka subsidy account mein aa gaya. Rs 200 credit hua hai.",
        "Passport size photos chahiye. Studio wala Rs 50 mein 8 copies de raha hai.",
        "E-Shram card banwaya hai online. Registration number aa gaya hai.",
        "Property registration ke liye stamp duty kitni lagegi? 3 BHK flat hai.",
        "Birth certificate ki copy chahiye. Municipal office se milegi ya online?",
        "Pension ka status check karna hai. Post office mein jaake pata karungi.",
        "Ration ki dukaan pe aaj chaawal aur dal mila. Line mein 30 minute lage.",
        "Aaj Jal Board ka bill bhara online. Rs 850 tha. Receipt save kar li hai.",
        "Driving test ke liye slot book kiya hai online. Next Thursday ko hai appointment.",
    ],
    "Emergency Conversation": [
        "Kitchen mein chhoti si aag lagi thi par turant bujha di. Sab safe hain, chinta mat karo.",
        "Dada ji ke saath hospital mein hoon. Chakkar aa gaya tha par doctor ne bola theek hain ab.",
        "Bijli 3 ghante se gayi hui hai. Electricity board ko call kiya. Shaam tak aayegi bole.",
        "Highway pe minor car accident hua. Koi hurt nahi hai. Insurance company ko inform kar diya.",
        "Bathroom mein pipe fat gaya. Plumber ko bulaya hai, aa raha hai. Main valve band kar diya.",
        "Bahut barish ke wajah se road pe paani bhara hai. Drive karna mushkil hai. Late aaungi ghar.",
        "Park mein gir gayi, pair mein halka moch aaya hai. Ice laga rahi hoon. Aane ki zaroorat nahi.",
        "Building ke entrance pe aawara kutta hai. Municipal helpline ko call kiya. Koi bhejenge.",
        "Security guard ko suspicious bag mila. Police ko bulaya. Check kiya toh khana tha usme.",
        "Phone paani mein gir gaya par bacha liya. Abhi kaam kar raha hai. Dry karne band kar rahi hoon.",
        "Ghar mein ek lizard aa gayi hai badi wali. Darwaza khol ke nikaalne ki koshish kar rahe hain.",
        "Bacche ko bukhar aa gaya hai. Paracetamol di hai. Agar kal tak nahi utra toh doctor le jaungi.",
        "Lift stuck ho gayi thi 10 minute ke liye. Maintenance ne fix kar diya. Main theek hoon.",
        "Stray dogs raat ko bahut bhonk rahe hain. Society guard se baat ki hai. Dekhega woh.",
        "Gas cylinder ka regulator kharab ho gaya. Agency ko call kiya hai. Kal naya bhejenge.",
        "Bijli ka wire spark kar raha tha. Electrician ko bulaya hai. Tab tak main switch off hai.",
        "Pados mein ambulance aayi thi. Aunty ji ko hospital le gaye. Unke bete ko inform kar diya.",
        "Baccha cycle se gir gaya. Ghutne pe chot lagi hai. First aid kit se bandage kar diya.",
        "Raat ko koi darwaza knock kar raha tha. Security guard check kiya, delivery boy tha galat floor pe.",
        "Geyser se paani leak ho raha hai. Plumber kal aayega. Tab tak bucket se kaam chala rahe hain.",
    ],
}

SAFE_ACTION = "No action required. This appears to be a normal conversation."


# ====================================================================
# SCAM TEMPLATES (HINDI) - 15 categories, Devanagari script
# ====================================================================

SCAM_DATA_HINDI = {
    "Family Impersonation": {
        "templates": [
            "भाई, मुझे बहुत ज़रूरत है। मेरा एक्सीडेंट हो गया है। {amount} रुपये भेज दो तुरंत। किसी को मत बताना।",
            "मम्मी को मत बताना, मेरा फोन खो गया। मैं {place} में फंसा हूं। {amount} रुपये चाहिए अभी। जल्दी करो।",
            "भाई, मैं अस्पताल में हूं। {amount} रुपये चाहिए इलाज के लिए। तुरंत भेज दो यूपीआई पर। बाद में बताऊंगा।",
            "यह मैं हूं, तुम्हारा {relation}। मेरा {problem} हो गया। {amount} रुपये तुरंत भेजो। किसी को मत बताओ।",
            "जल्दी करो प्लीज, {relation} बोल रहा हूं। {problem}। मुझे {amount} रुपये चाहिए अभी के अभी। पापा को मत बोलना।",
            "बेटा, मुझे परेशानी में हूं। {problem}। {amount} रुपये भेज दो यूपीआई से। किसी को पता मत चलने देना।",
            "भैया, {problem} हो गया है। {amount} रुपये की जरूरत है। परिवार को मत बताना अभी।",
            "मेरी बहुत बुरी स्थिति है। {place} में हूं, {problem}। {amount} दे दो प्लीज, किसी को मत बताना।",
        ],
        "vars": {
            "relation": ["भाई", "भैया", "दीदी", "बहन", "भतीजा", "बेटा"],
            "problem": ["एक्सीडेंट हो गया", "पुलिस ने पकड़ा", "अस्पताल में हूं", "पैसा चोरी हो गया", "फंस गया हूं"],
            "amount": ["10,000", "20,000", "25,000", "40,000", "50,000", "75,000"],
            "place": ["दिल्ली", "मुंबई", "लखनऊ", "हाईवे पर", "स्टेशन पर", "दूसरे शहर में"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 1, "secrecy_request": 1,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 0},
        "threat_level": "HIGH",
        "action": "Verify the caller through an independent communication channel before transferring money.",
    },

    "Kidnapping & Extortion Threat": {
        "templates": [
            "मैंने तुम्हारे {victim} को किडनैप कर लिया है। मुझे {amount} रुपये की फिरौती चाहिए। पुलिस को मत बताना।",
            "तुम्हारा {victim} मेरे कब्जे में है। अगर जिंदा देखना चाहते हो तो तुरंत {amount} रुपये भेज दो।",
            "मैंने तुम्हारे {victim} को उठवा लिया है। {amount} रुपये फिरौती चाहिए आज ही, वरना जान से मार दूंगा।",
            "सुनो ध्यान से। तुम्हारे {victim} को हमने किडनैप किया है। {amount} रुपये ट्रांसफर करो अभी।",
            "तुम्हारे {victim} की जान खतरे में है। {amount} रुपये तुरंत भेजो वरना लाश मिलेगी। किसी को मत बोलना।",
            "तुम्हारे {victim} को हमने पकड़ा है। {amount} रुपये दो वरना बहुत बुरा होगा। पुलिस मत बुलाना।",
            "मैंने किडनैप किया है तुम्हारे {victim} को। {amount} रुपये फिरौती है। देरी की तो गोली मार दूंगा।",
            "आपका {victim} हमारे साथ है। 2 घंटे में {amount} रुपये ट्रांसफर करो। पुलिस को बताया तो मार दूंगा।",
        ],
        "vars": {
            "victim": ["बेटे", "बेटी", "बच्चे", "भाई", "परिवार के सदस्य"],
            "amount": ["50,000", "1,00,000", "2,00,000", "5,00,000"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 1, "secrecy_request": 1,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 1},
        "threat_level": "CRITICAL",
        "action": "Do not transfer money. Immediately report the extortion/kidnapping threat to the local Police and Cyber Crime helpline 1930.",
    },

    "Friend Impersonation": {
        "templates": [
            "यार, मैं {name} बोल रहा हूं। {problem}। {amount} रुपये चाहिए अभी। बाद में लौटाऊंगा। ग्रुप में मत बोलना।",
            "दोस्त, मेरी मदद कर। {name} हूं। {problem}। {amount} रुपये दे दो। किसी को मत बता।",
            "भाई {name} बोल रहा हूं। मेरी {problem} हो गई। क्या तू {amount} रुपये भेज सकता है? वापस कर दूंगा।",
            "यार प्लीज, {name} हूं। {problem}। बहुत जरूरत है {amount} रुपये की। तुरंत भेज दे। ग्रुप में मत बोल।",
            "{name} हूं मैं। {problem}। {amount} रुपये भेज दो। वापस कर दूंगा। सीक्रेट रख।",
            "यार, {name} बोल रहा हूं। मेरा {problem}। {amount} रुपये की बहुत जरूरत है। मदद कर यार।",
        ],
        "vars": {
            "name": ["राहुल", "प्रिया", "अमित", "स्नेहा", "विक्रम", "रोहित", "अंकिता", "पूजा"],
            "problem": ["स्टेशन पर पर्स खो गया", "फोन चोरी हो गया", "बिना पैसे के फंसा हूं", "बाइक एक्सीडेंट हुआ",
                       "इमरजेंसी कैश चाहिए", "अस्पताल का बिल भरना है"],
            "amount": ["5,000", "8,000", "10,000", "15,000", "20,000"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 1, "secrecy_request": 1,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 0},
        "threat_level": "HIGH",
        "action": "Contact the person directly using a known phone number to verify their identity.",
    },

    "Police Impersonation": {
        "templates": [
            "मैं {rank} बोल रहा हूं साइबर क्राइम से। आपके आधार पर {case}। {amount} रुपये सेटलमेंट दो वरना गिरफ्तारी होगी।",
            "ध्यान से सुनिए, {rank} बोल रहा हूं। {case}। 2 घंटे में {amount} रुपये जमा नहीं किया तो घर पर पुलिस आएगी।",
            "यह पुलिस हेडक्वार्टर से कॉल है। {rank} बोल रहा हूं। {case}। {amount} रुपये केस क्लोजर फीस भेजिए।",
            "आपके खिलाफ {case}। मैं {rank} हूं। {amount} रुपये जमा करो वेरिफिकेशन अकाउंट में। वकील को मत बुलाओ।",
            "यह गंभीर मामला है। मैं {rank} हूं। {case}। {amount} रुपये तुरंत ट्रांसफर करें वरना वारंट जारी होगा।",
            "आपके नाम पर वारंट है। {rank} बोल रहा हूं। {case}। अभी {amount} रुपये सिक्योरिटी डिपॉजिट करो।",
            "{rank} यहां से बोल रहे हैं। आपके खिलाफ एफआईआर दर्ज है। {amount} रुपये भरो वरना जेल जाओगे।",
            "साइबर सेल से {rank} हूं। {case}। {amount} रुपये जमा करें वरना गिरफ्तार कर लिया जाएगा।",
        ],
        "vars": {
            "rank": ["इंस्पेक्टर शर्मा", "सब-इंस्पेक्टर", "एसीपी साहब", "साइबर सेल ऑफिसर", "डीसीपी ऑफिस से"],
            "case": ["क्रिमिनल कंप्लेंट फाइल हुई है", "आपका अकाउंट मनी लॉन्ड्रिंग में शामिल है",
                     "आपकी आईडेंटिटी फ्रॉड में उपयोग हुई है", "आपके नाम पर एफआईआर है",
                     "आपका फोन नंबर संदिग्ध गतिविधि में है"],
            "amount": ["50,000", "75,000", "1,00,000", "1,50,000", "2,00,000"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 0, "secrecy_request": 1,
                       "authority_impersonation": 1, "otp_request": 0, "credential_request": 0, "threat_detected": 1},
        "threat_level": "CRITICAL",
        "action": "Hang up and contact the local police station directly. Real police never demand money over phone.",
    },

    "Government Impersonation": {
        "templates": [
            "यह {dept} से कॉल है। {scenario}। {amount} रुपये जुर्माना भरो वरना कानूनी कार्रवाई होगी। 24 घंटे का समय है।",
            "{dept} से आधिकारिक नोटिस। {scenario}। {amount} रुपये कंप्लायंस फीस ट्रांसफर करें 3 घंटे में।",
            "मैं {dept} का अधिकारी बोल रहा हूं। {scenario}। {amount} रुपये आज ही जमा करो। पासपोर्ट कैंसिल होगा।",
            "{dept} की तरफ से अर्जेंट कॉल। {scenario}। {amount} रुपये वेरिफिकेशन फीस भेजिए। नहीं तो संपत्ति जब्त होगी।",
            "आपको {dept} से फाइनल नोटिस मिल रहा है। {scenario}। {amount} रुपये जमा करो आज ही।",
            "{dept} का ऑफिसर हूं। {scenario}। {amount} रुपये देने होंगे नहीं तो अरेस्ट वारंट जारी होगा।",
            "यह {dept} से अटोमेटेड संदेश है। {scenario}। {amount} रुपये सेटलमेंट जमा करें। कल तक का वक्त है।",
            "{dept} से इमरजेंसी कॉल। {scenario}। {amount} रुपये अभी भेजें वरना अकाउंट फ्रीज होगा।",
        ],
        "vars": {
            "dept": ["इनकम टैक्स डिपार्टमेंट", "ट्राई", "कस्टम्स विभाग", "आरबीआई", "वित्त मंत्रालय"],
            "scenario": ["आपके पैन कार्ड पर टैक्स चोरी पाई गई है", "आपका आधार अवैध गतिविधि में उपयोग हुआ है",
                        "आपका मोबाइल नंबर 24 घंटे में बंद होगा", "आपके बैंक खाते फ्रीज होने वाले हैं",
                        "आपके नाम पर संदिग्ध पार्सल है"],
            "amount": ["25,000", "50,000", "1,00,000", "2,00,000", "3,00,000"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 0, "secrecy_request": 1,
                       "authority_impersonation": 1, "otp_request": 0, "credential_request": 0, "threat_detected": 1},
        "threat_level": "CRITICAL",
        "action": "No government agency demands payment over phone. Contact the department through official channels.",
    },

    "Bank Fraud": {
        "templates": [
            "{bank} से कॉल है। {scenario}। खाता बचाने के लिए अभी ओटीपी बताइए जो आपके फोन पर आया है।",
            "{bank} फ्रॉड प्रिवेंशन टीम। {scenario}। कृपया 6 अंकों का ओटीपी शेयर करें वेरिफिकेशन के लिए।",
            "{bank} से बोल रहे हैं। {scenario}। सिक्योरिटी के लिए अपना ओटीपी और कार्ड के अंतिम 4 अंक बताइए।",
            "नमस्ते, {bank} का फ्रॉड टीम बोल रहा है। {scenario}। तुरंत ओटीपी शेयर करें खाता सुरक्षित करने के लिए।",
            "{bank} सिक्योरिटी डिपार्टमेंट। {scenario}। ओटीपी बताइए 10 मिनट में वरना खाता परमानेंट लॉक हो जाएगा।",
            "{bank} से महत्वपूर्ण कॉल। {scenario}। कार्ड के पीछे का सीवीवी और ओटीपी बताइए।",
            "यह {bank} का टेक्निकल टीम है। {scenario}। अपना इंटरनेट बैंकिंग पासवर्ड शेयर करें वेरिफिकेशन के लिए।",
            "{bank} से अर्जेंट कॉल। {scenario}। नेट बैंकिंग यूजर आईडी और पासवर्ड बताइए खाता सुरक्षित करने हेतु।",
        ],
        "vars": {
            "bank": ["एसबीआई", "एचडीएफसी बैंक", "आईसीआईसीआई बैंक", "एक्सिस बैंक", "पीएनबी", "कोटक बैंक"],
            "scenario": ["आपके खाते से 45,000 रुपये का संदिग्ध ट्रांजेक्शन हुआ है", "आपका डेबिट कार्ड कंप्रोमाइज हुआ है",
                        "आपका खाता ब्लॉक होने वाला है", "नेट बैंकिंग में अनऑथराइज्ड लॉगिन हुआ है",
                        "आपके खाते में संदिग्ध गतिविधि है"],
        },
        "indicators": {"urgency": 1, "financial_request": 0, "emotional_manipulation": 0, "secrecy_request": 0,
                       "authority_impersonation": 1, "otp_request": 1, "credential_request": 1, "threat_detected": 1},
        "threat_level": "CRITICAL",
        "action": "Never share OTP, PIN, or passwords. Call your bank's official helpline number printed on your card.",
    },

    "OTP Scam": {
        "templates": [
            "नमस्ते, {caller} हूं। {pretext}। आपके नंबर पर जो 6 अंकों का कोड आया है वो बता दीजिए। बहुत अर्जेंट है।",
            "{caller} से कॉल है। {pretext}। आपके {platform} पर जो ओटीपी आया है वो बता दीजिए। 5 मिनट में एक्सपायर होगा।",
            "मैं {caller} बोल रहा हूं। मेरा ओटीपी गलत नंबर पर चला गया। {pretext}। वो कोड बता दो।",
            "हेलो, {caller} हूं। {pretext}। {platform} का ओटीपी शेयर कर दीजिए जल्दी, वरना प्रोसेस कैंसिल हो जाएगा।",
            "{caller} बोल रहा हूं {platform} से। {pretext}। ओटीपी बताइए तुरंत। कॉल रिकॉर्ड हो रही है।",
            "यह {caller} है। {pretext}। आपके {platform} अकाउंट के लिए ओटीपी आया होगा। जल्दी बताइए।",
            "{caller} से। {pretext}। ओटीपी शेयर करना जरूरी है वरना {platform} अकाउंट ब्लॉक हो जाएगा।",
            "मैं {caller} हूं। गलती से आपके नंबर पर {platform} का ओटीपी आ गया। प्लीज बता दीजिए।",
        ],
        "vars": {
            "pretext": ["केवाईसी अपडेट हो रहा है", "रिफंड प्रोसेस हो रहा है", "रिवॉर्ड पॉइंट्स एक्सपायर हो रहे हैं",
                       "आपका मोबाइल वेरिफाई करना है", "कैशबैक क्लेम करना है", "अकाउंट रिएक्टिवेशन के लिए"],
            "caller": ["कस्टमर केयर", "एग्जिक्यूटिव", "वेरिफिकेशन ऑफिसर", "सपोर्ट टीम", "टेक्निकल सपोर्ट"],
            "platform": ["पेटीएम", "फोनपे", "गूगल पे", "अमेजॉन", "फ्लिपकार्ट", "बैंक", "यूपीआई", "व्हाट्सएप"],
        },
        "indicators": {"urgency": 1, "financial_request": 0, "emotional_manipulation": 0, "secrecy_request": 0,
                       "authority_impersonation": 0, "otp_request": 1, "credential_request": 0, "threat_detected": 0},
        "threat_level": "HIGH",
        "action": "Never share OTP with anyone. OTPs are for your personal transactions only.",
    },

    "PIN/Credential Scam": {
        "templates": [
            "{bank} का टेक्निकल टीम बोल रहा है। {pretext}। एटीएम पिन और नेट बैंकिंग पासवर्ड शेयर करें।",
            "प्रिय ग्राहक, {bank} से हैं। {pretext}। अपना डेबिट कार्ड नंबर, सीवीवी और एक्सपायरी डेट बताइए।",
            "{bank} से वेरिफिकेशन कॉल। {pretext}। इंटरनेट बैंकिंग यूजर आईडी और पासवर्ड दीजिए।",
            "{bank} का {caller} बोल रहा है। {pretext}। कार्ड के 16 अंक, सीवीवी और पिन बताइए।",
            "नमस्ते, {bank} का {caller} हूं। {pretext}। अपना पासवर्ड और कार्ड डिटेल्स शेयर करें।",
            "यह {bank} का {caller} है। {pretext}। तुरंत एटीएम पिन बताइए वरना कार्ड ब्लॉक हो जाएगा।",
            "{bank} से {caller} बोल रहा है। {pretext}। यूपीआई पिन और आधार के अंतिम 4 अंक शेयर करें।",
            "{caller} यहां {bank} से। {pretext}। सिक्योरिटी अपडेट के लिए नेट बैंकिंग क्रेडेंशियल चाहिए।",
        ],
        "vars": {
            "pretext": ["नेट बैंकिंग अपग्रेड हो रही है", "आपके अकाउंट की री-वेरिफिकेशन जरूरी है",
                       "अनजान डिवाइस से लॉगिन डिटेक्ट हुआ", "कार्ड रिन्यूअल के लिए", "केवाईसी अपडेट मैंडेटरी है"],
            "bank": ["एसबीआई", "एचडीएफसी बैंक", "आईसीआईसीआई बैंक", "एक्सिस बैंक", "पीएनबी", "कोटक बैंक"],
            "caller": ["टेक्निकल टीम", "सिक्योरिटी ऑफिसर", "वेरिफिकेशन ऑफिसर", "फ्रॉड प्रिवेंशन ऑफिसर"],
        },
        "indicators": {"urgency": 1, "financial_request": 0, "emotional_manipulation": 0, "secrecy_request": 0,
                       "authority_impersonation": 1, "otp_request": 0, "credential_request": 1, "threat_detected": 0},
        "threat_level": "HIGH",
        "action": "Banks never ask for PIN, CVV, or passwords over phone. Never share these with anyone.",
    },

    "Investment Scam": {
        "templates": [
            "बधाई हो! {scheme} में निवेश करें सिर्फ {amount} रुपये। गारंटीड 300% रिटर्न 3 महीने में। आज ही जॉइन करें।",
            "{scheme} अभी ओपन है। न्यूनतम {amount} रुपये। रिटर्न गारंटीड। 2 घंटे में रजिस्टर करें। किसी को मत बताना।",
            "विशेष ऑफर: {scheme}। {amount} रुपये निवेश करें और वीकली पेआउट पाएं। यह ऑफर सिर्फ आज के लिए है।",
            "{scheme} से लोग करोड़पति बन रहे हैं। {amount} रुपये से शुरू करें। कोई रिस्क नहीं। मनी बैक गारंटी।",
            "आपको {scheme} के लिए चुना गया है। {amount} रुपये लगाएं, 500% रिटर्न मिलेगा। ऑफर आज एक्सपायर।",
            "{scheme} में {amount} रुपये निवेश करें। 100% सेफ और लीगल। पैसिव इनकम शुरू करें आज से।",
            "हेलो, {scheme} का एक्सक्लूसिव ऑफर है। {amount} रुपये लगाइए, पैसे डबल होंगे 45 दिन में। लिमिटेड सीट्स।",
            "{scheme} में {amount} रुपये ट्रांसफर करें। रिकॉर्ड प्रॉफिट आ रहे हैं। पहला पेआउट एक हफ्ते में।",
        ],
        "vars": {
            "scheme": ["गारंटीड स्टॉक मार्केट प्लान", "क्रिप्टो ट्रेडिंग ऑपर्चुनिटी", "40% रिटर्न वाला म्यूचुअल फंड",
                      "एक्सक्लूसिव रियल एस्टेट डील", "एआई ट्रेडिंग बॉट", "फॉरेक्स ट्रेडिंग विदआउट रिस्क"],
            "amount": ["10,000", "25,000", "50,000", "1,00,000"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 1, "secrecy_request": 0,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 0},
        "threat_level": "HIGH",
        "action": "Verify investments through SEBI registered channels. No legitimate investment guarantees fixed returns.",
    },

    "Job Scam": {
        "templates": [
            "बधाई हो! {job} के लिए चुने गए हैं। सैलरी 25,000-50,000 रुपये प्रतिमाह। रजिस्ट्रेशन फीस {amount} रुपये दें।",
            "जॉब अलर्ट: {job} पोजिशन ओपन है। कोई अनुभव नहीं चाहिए। {amount} रुपये प्रोसेसिंग फीस। यूपीआई से पे करें।",
            "{job} का मौका - घर से काम करें। रोजाना 1,000-5,000 रुपये कमाएं। रजिस्ट्रेशन {amount} रुपये।",
            "आपके लिए {job} का ऑफर है। महीने में 40,000 रुपये+। एक बार फीस {amount} रुपये। आज ही पे करें।",
            "चुने गए हैं आप {job} के लिए! घर बैठे कमाएं। फीस {amount} रुपये यूपीआई पर भेजें। लॉगिन तुरंत मिलेगा।",
            "प्रिय उम्मीदवार, {job} वैकेंसी उपलब्ध है। {amount} रुपये ऑनबोर्डिंग के लिए दें। आज से कमाई शुरू।",
            "क्या आप एक्स्ट्रा इनकम चाहते हैं? {job} में मौका है। रजिस्ट्रेशन {amount} रुपये। छात्र और गृहणियां स्वागत है।",
            "नया {job} का ऑफर। {amount} रुपये फीस दें और तुरंत काम शुरू करें। आज तक वैलिड।",
        ],
        "vars": {
            "job": ["घर से डेटा एंट्री", "सोशल मीडिया मार्केटिंग", "ऑनलाइन सर्वे काम", "पार्ट-टाइम टाइपिंग",
                   "अमेजॉन रिव्यू जॉब", "यूट्यूब वीडियो लाइकिंग", "कॉपी पेस्ट जॉब"],
            "amount": ["499", "999", "1,499", "2,500", "4,999"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 0, "secrecy_request": 0,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 0},
        "threat_level": "MEDIUM",
        "action": "Legitimate employers never ask for money upfront. Verify through the company's official website.",
    },

    "Loan Scam": {
        "templates": [
            "तुरंत {loan_type} {loan_amt} रुपये 2% ब्याज पर। कोई दस्तावेज नहीं। प्रोसेसिंग फीस {amount} रुपये। आज ही वैलिड।",
            "आपका {loan_type} {loan_amt} रुपये प्री-अप्रूव्ड है। {amount} रुपये इंश्योरेंस और फीस भेजें। लोन 24 घंटे में।",
            "प्रिय ग्राहक, {loan_type} {loan_amt} रुपये स्वीकृत। {amount} रुपये जीएसटी और फीस जमा करें। आज क्रेडिट होगा।",
            "अर्जेंट: आपका {loan_type} आवेदन {loan_amt} रुपये अप्रूव्ड। {amount} रुपये वेरिफिकेशन चार्ज दें। देरी = कैंसिल।",
            "{loan_type} ऑफर: {loan_amt} रुपये सबसे कम ब्याज पर। {amount} रुपये एक बार फीस। 2 घंटे में डिस्बर्समेंट।",
            "बधाई हो! {loan_type} {loan_amt} रुपये रेडी। सिर्फ {amount} रुपये प्रोसेसिंग फीस। जीरो डॉक्यूमेंटेशन।",
            "{loan_type} {loan_amt} बिना कोलैटरल के। {amount} रुपये सिक्योरिटी डिपॉजिट भेजें। आज ही मिलेगा।",
            "प्री-अप्रूव्ड {loan_type} {loan_amt} रुपये। {amount} रुपये जमा करें तुरंत। ऑफर सिर्फ आज के लिए है।",
        ],
        "vars": {
            "loan_type": ["पर्सनल लोन", "बिजनेस लोन", "इंस्टेंट लोन", "एजुकेशन लोन", "इमरजेंसी लोन"],
            "amount": ["2,000", "5,000", "8,000", "12,000", "15,000"],
            "loan_amt": ["1,00,000", "2,00,000", "5,00,000", "10,00,000"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 0, "secrecy_request": 0,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 0},
        "threat_level": "MEDIUM",
        "action": "No genuine bank charges processing fees before loan disbursement. Verify through official channels.",
    },

    "Extortion": {
        "templates": [
            "हम जानते हैं तुम कौन हो। {threat}। 24 घंटे में {amount} रुपये भेजो वरना सब कॉन्टैक्ट्स को भेज देंगे।",
            "आखिरी चेतावनी। {threat}। {amount} रुपये ट्रांसफर करो। पुलिस को बुलाया तो और बुरा होगा।",
            "यह तुम्हारी आखिरी मौका है। {threat}। {amount} रुपये दो वरना सोशल मीडिया पर सब एक्सपोज़ करेंगे।",
            "{threat}। {amount} रुपये भेजो नहीं तो पब्लिकली रिलीज करेंगे। 48 घंटे का समय है।",
            "हमारे पास सब कुछ है। {threat}। {amount} रुपये ट्रांसफर करो यूपीआई से। कोई पुलिस नहीं। कोई बातचीत नहीं।",
            "{threat}। तुम्हारे एम्प्लॉयर को भी भेजेंगे। {amount} रुपये जमा करो आज रात तक।",
            "तुम जानते हो क्या होगा अगर {threat}। {amount} दे दो और सब खत्म। वरना कंसिक्वेंसेस भोगो।",
            "{threat}। {amount} रुपये गूगल पे पर भेजो। 6 घंटे हैं। हम देख रहे हैं।",
        ],
        "vars": {
            "threat": ["तुम्हारी प्राइवेट फोटो और वीडियो हैं हमारे पास", "हमने तुम्हारी स्क्रीन रिकॉर्ड की है",
                      "तुम्हारी ब्राउजिंग हिस्ट्री है हमारे पास", "हमने तुम्हारा वेबकैम हैक किया है",
                      "तुम्हारे प्राइवेट मैसेज हैं हमारे पास"],
            "amount": ["50,000", "1,00,000", "2,00,000"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 1, "secrecy_request": 1,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 1},
        "threat_level": "CRITICAL",
        "action": "Do not pay. Report to Cyber Crime helpline 1930 and local police station immediately.",
    },

    "Blackmail": {
        "templates": [
            "मेरे पास {leverage} है। अगर पति/पत्नी और कलीग्स को नहीं दिखाना तो {amount} रुपये भेजो।",
            "हमारे पास {leverage} है और जानते हैं आप कहां काम करते हो। {amount} रुपये दो। वरना शेयर।",
            "{leverage} है मेरे पास। {amount} रुपये गूगल पे या फोनपे से भेजो 24 घंटे में।",
            "यह मजाक नहीं है। {leverage} है मेरे पास। {amount} रुपये दोगे तो परमानेंट डिलीट। इग्नोर करोगे तो रेप्यूटेशन खत्म।",
            "तुम्हारी {leverage} पब्लिक करनी है या {amount} दोगे? चॉइस तुम्हारी है। टाइम कम है।",
            "{leverage} है मेरे पास। तुम्हारे परिवार को दिखाऊंगा अगर {amount} रुपये नहीं मिले 48 घंटे में।",
            "हमारे पास है {leverage}। {amount} रुपये दो या पब्लिक अपमान का सामना करो।",
            "हम सब कुछ जानते हैं। {leverage}। {amount} रुपये ट्रांसफर करो वरना एम्प्लॉयर को भेजेंगे।",
        ],
        "vars": {
            "leverage": ["चैट स्क्रीनशॉट्स", "डेटिंग ऐप प्रोफाइल", "डिलीटेड सोशल मीडिया पोस्ट",
                        "प्राइवेट मैसेज", "वीडियो कॉल रिकॉर्डिंग्स", "पर्सनल फोटोज"],
            "amount": ["25,000", "50,000", "1,00,000"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 1, "secrecy_request": 1,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 1},
        "threat_level": "CRITICAL",
        "action": "Do not pay. Report to Cyber Crime helpline 1930 and local police station immediately.",
    },

    "Emergency Money Scam": {
        "templates": [
            "नमस्ते, {relation} का {emergency} हुआ है। उन्होंने कहा आपको कॉल करें। {amount} रुपये चाहिए तुरंत इलाज के लिए।",
            "यह अस्पताल से कॉल है। {relation} को {emergency} के बाद लाए हैं। डॉक्टर को {amount} रुपये चाहिए। जल्दी भेजिए।",
            "प्लीज मत घबराइए। {relation} का {emergency} हुआ है। {amount} रुपये तुरंत ट्रांसफर करें।",
            "अर्जेंट: {relation} खतरे में है। {emergency} स्थिति है। {amount} रुपये तुरंत भेजें। परिवार को मत बताओ अभी।",
            "{relation} का {emergency} हो गया। अस्पताल वाले {amount} रुपये मांग रहे हैं। प्लीज जल्दी भेजिए।",
            "मैं {relation} के साथ हूं। उनका {emergency} हुआ है। {amount} रुपये चाहिए तुरंत। प्लीज मदद करें।",
            "इमरजेंसी कॉल: {relation} को {emergency} हुआ। {amount} रुपये तुरंत चाहिए। हम अस्पताल में हैं।",
            "यह गंभीर है। {relation} का {emergency} हुआ है। {amount} रुपये एक घंटे में चाहिए। परिवार को अभी मत बताओ।",
        ],
        "vars": {
            "relation": ["आपके पापा", "आपकी मम्मी", "आपके पति", "आपकी पत्नी", "आपका बेटा", "आपके दादा जी"],
            "emergency": ["मेडिकल इमरजेंसी", "रोड एक्सीडेंट", "हार्ट अटैक", "गंभीर चोट", "सर्जरी जरूरी है"],
            "amount": ["20,000", "35,000", "50,000", "75,000", "1,00,000"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 1, "secrecy_request": 1,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 0},
        "threat_level": "HIGH",
        "action": "Verify the emergency by contacting the person or hospital directly through known numbers.",
    },

    "Fake Parcel/Customs Scam": {
        "templates": [
            "कस्टम्स विभाग से कॉल है। {item} आपके नाम और आधार पर रजिस्टर्ड है। {amount} रुपये क्लीयरेंस फीस दो वरना केस।",
            "कूरियर कंपनी से बोल रहे हैं। {item} बॉर्डर पर रोका गया। आपकी आईडी थी। {amount} रुपये कस्टम ड्यूटी दें।",
            "ध्यान दें: {item} एयरपोर्ट पर सीज हुआ है। आपका नाम लिंक्ड है। {amount} रुपये ट्रांसफर करें 4 घंटे में।",
            "फाइनल नोटिस। {item} अधिकारियों के पास है। {amount} रुपये वेरिफिकेशन फीस दो वरना पुलिस आएगी आज।",
            "चेतावनी: {item} जांच के अधीन है। आपका आधार लिंक्ड है। {amount} रुपये दो वरना पासपोर्ट कैंसिल।",
            "{item} कस्टम्स ने पकड़ा है। आपके नाम पर है। {amount} रुपये जमा करें क्लीयरेंस के लिए। अर्जेंट है।",
            "यह कस्टम्स विभाग से आधिकारिक कॉल है। {item} आपके पते पर रजिस्टर है। {amount} रुपये जुर्माना भरो।",
            "यह कूरियर सेवा है। {item} को इंटरसेप्ट किया गया है। {amount} रुपये दें वरना क्रिमिनल चार्ज लगेंगे।",
        ],
        "vars": {
            "item": ["अवैध ड्रग्स वाला पार्सल", "नकली करेंसी का पैकेज", "प्रतिबंधित सामग्री वाला कूरियर",
                    "संदिग्ध सामग्री वाला पैकेज", "अंतर्राष्ट्रीय अवैध पार्सल"],
            "amount": ["15,000", "25,000", "50,000", "1,00,000"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 0, "secrecy_request": 0,
                       "authority_impersonation": 1, "otp_request": 0, "credential_request": 0, "threat_detected": 1},
        "threat_level": "CRITICAL",
        "action": "No customs or courier service demands payment over phone. Verify through official channels.",
    },

    "Financial Manipulation": {
        "templates": [
            "अच्छी खबर! {tactic}। क्लेम करने के लिए {amount} रुपये प्रोसेसिंग फीस दें। पूरी राशि 48 घंटे में मिलेगी।",
            "बधाई हो! {tactic}। {amount} रुपये वेरिफिकेशन चार्ज दें और राशि तुरंत क्रेडिट होगी। आज ही वैलिड।",
            "नमस्ते, {tactic}। आप पात्र हैं। {amount} रुपये सर्विस चार्ज दें। एक बार की फीस है।",
            "प्रिय ग्राहक, {tactic}। {amount} रुपये नॉमिनल फीस दें फंड रिलीज करने के लिए। जल्दी करो, एक्सपायर होगा।",
            "{tactic}। लेकिन {amount} रुपये सरकारी प्रोसेसिंग चार्ज पहले देने होंगे। अभी पे करें।",
            "आपके खाते में {tactic}। {amount} रुपये दे दीजिए प्रोसेसिंग के लिए। तुरंत राशि आ जाएगी।",
            "एक्साइटिंग ऑफर: {tactic}। सिर्फ {amount} रुपये फीस में क्लेम करें। ऑफर आज रात तक है।",
            "{tactic}। {amount} रुपये पे करें और पैसे ले जाएं। यह असली सरकारी योजना है।",
        ],
        "vars": {
            "tactic": ["50,000 रुपये का टैक्स रिफंड पेंडिंग है आपका", "अनक्लेम्ड इंश्योरेंस पेआउट है आपका",
                      "सरकारी सब्सिडी के लिए चुने गए हैं", "10,000 रुपये कैशबैक रिवॉर्ड पेंडिंग है",
                      "एलआईसी का बोनस मैच्योर हुआ है", "इनकम टैक्स रिफंड पेंडिंग है आपका",
                      "पीएम योजना के तहत 1 लाख रुपये मिलेगा"],
            "amount": ["1,000", "2,000", "3,000", "5,000", "7,500"],
        },
        "indicators": {"urgency": 1, "financial_request": 1, "emotional_manipulation": 1, "secrecy_request": 0,
                       "authority_impersonation": 0, "otp_request": 0, "credential_request": 0, "threat_detected": 0},
        "threat_level": "MEDIUM",
        "action": "No legitimate organization asks for fees to release refunds. Verify through official channels.",
    },
}


# ====================================================================
# SAFE TEMPLATES (HINDI) - 7 categories, Devanagari script
# ====================================================================

SAFE_DATA_HINDI = {
    "Family Conversation": [
        "हाय मम्मी, मैं ऑफिस पहुंच गई। ट्रैफिक बहुत था आज। 7 बजे तक आ जाऊंगी घर।",
        "दूध और ब्रेड ले आना घर आते वक्त। पापा की दवाई भी लेनी है फार्मेसी से।",
        "हैप्पी बर्थडे! मैंने केक ऑर्डर किया है। 5 बजे तक आ जाएगा। पूरा परिवार आ रहा है रात को।",
        "भाई को अस्पताल ले जा रही हूं रेगुलर चेकअप के लिए। दोपहर के बाद निकलेंगे।",
        "स्कूल में हूं। टीचर मिलना चाहती हैं बच्चे की प्रगति के बारे में। रूटीन मीटिंग है।",
        "दादी जी आज बेहतर महसूस कर रही हैं। डॉक्टर ने कहा कल घर आ सकती हैं।",
        "सैलरी क्रेडिट हो गई आज। ज्वाइंट अकाउंट में ट्रांसफर करना है तो बता दो कितना।",
        "मम्मी, हॉस्टल पहुंच गई। चिंता मत करो। वॉर्डन बहुत सख्त है सेफ्टी के बारे में।",
        "पापा, स्कूल की फीस अगले हफ्ते ड्यू है। 15,000 रुपये है इस सेमेस्टर। स्कूल अकाउंट में भेज देना।",
        "रविवार को लंच के लिए रेस्तरां बुक किया है। नया वाला है मॉल के पास। पूरा परिवार आ सकता है।",
        "नानी के लिए दवाई ऑर्डर किया है ऑनलाइन। कल तक आ जाएगी। उनका बीपी नॉर्मल है अब।",
        "घर का बिजली का बिल आया है 3,500 रुपये। ऑनलाइन पे कर देती हूं आज रात।",
        "छोटू का रिजल्ट आ गया। बहुत अच्छे मार्क्स आए हैं। पार्टी रखते हैं वीकेंड पर।",
        "मौसम खराब है आज, जल्दी घर आ जाना। बारिश शुरू होने वाली है।",
        "बेटे की पैरेंट-टीचर मीटिंग है शुक्रवार को। 3 बजे जाना है स्कूल। तुम आ सकते हो?",
    ],
    "Friend Conversation": [
        "यार, वीकेंड पर फ्री हो? मूवी चलते हैं। नई एक्शन मूवी रिलीज हुई है।",
        "ब्रो, असाइनमेंट सबमिट किया? कल डेडलाइन है। मेरे दो पेज बाकी हैं अभी।",
        "नया जिम जॉइन किया है घर के पास। ट्रेनर बहुत अच्छा है। तू भी ट्राई कर।",
        "आज की लेक्चर के नोट्स शेयर कर दो। मुझे डेंटिस्ट के लिए अर्ली जाना पड़ा।",
        "अगले महीने रोड ट्रिप प्लान करते हैं। गोवा या पॉन्डिचेरी? क्या सोचते हो?",
        "प्रमोशन मिल गई! वीकेंड पर डिनर ट्रीट करूंगा। रेस्तरां तुम चुनो।",
        "कल रात का क्रिकेट मैच देखा? क्या इनक्रेडिबल फिनिश था! लास्ट ओवर में क्या हुआ यार!",
        "लैपटॉप खरीदना है, बजट 60,000 रुपये है। कोई सुझाव है?",
        "शनिवार को शिफ्टिंग में मदद कर सकता है? नए अपार्टमेंट में जा रहा हूं।",
        "कॉन्सर्ट के टिकट आए हैं! 2,500 रुपये प्रति टिकट। दो बुक करूं? जल्दी बताओ, बिक जाएंगे।",
        "जन्मदिन पार्टी के लिए वेन्यू सुझाओ। बजट 15,000 रुपये तक है। 20 लोग होंगे।",
        "कल का एग्जाम कैसा गया? मेरा तो ठीक-ठाक हुआ। पेपर लंबा था बहुत।",
        "फोटोग्राफी क्लब जॉइन किया है। वीकेंड पर फोटोवॉक है। आना है तो बताओ।",
        "ड्राइविंग टेस्ट पास हो गया! तीन अटेम्प्ट के बाद आखिरकार लाइसेंस मिला।",
        "वो रेस्तरां याद है जहां गए थे? नया मेनू आया है। शुक्रवार को चलें?",
    ],
    "Work Conversation": [
        "गुड मॉर्निंग। क्लाइंट मीटिंग 3 बजे रीशेड्यूल हो गई है। कैलेंडर अपडेट कर लेना।",
        "तिमाही रिपोर्ट भेज दी है। रिव्यू करके फीडबैक दे देना आज के अंत तक।",
        "प्रोजेक्ट डेडलाइन एक हफ्ते एक्सटेंड हुई है। अगले शुक्रवार तक सबमिट करना है अब।",
        "कल वर्क फ्रॉम होम करूंगा। सुबह प्लंबर आ रहा है। दोपहर तक ऑनलाइन आ जाऊंगा।",
        "टीम आउटिंग शनिवार को कन्फर्म है। एडवेंचर पार्क जा रहे हैं। बस 8 बजे निकलेगी।",
        "प्रेजेंटेशन फाइल भेज दो। कल की मीटिंग से पहले कुछ स्लाइड्स ऐड करनी हैं।",
        "ऑफिस वाईफाई पासवर्ड बदल गया है। नया पासवर्ड नोटिस बोर्ड पर है रिसेप्शन के पास।",
        "शुक्रवार तक टाइमशीट सबमिट कर दो। फाइनेंस को अर्जेंटली चाहिए मंथली पेरोल के लिए।",
        "सर्वर सुबह 30 मिनट डाउन था। आईटी टीम ने फिक्स कर दिया। सब नॉर्मल है अब।",
        "नए हायर की ऑनबोर्डिंग है अगले हफ्ते। ट्रेनिंग मटीरियल रेडी करनी है। मदद करोगे?",
        "क्लाइंट ने फीडबैक भेजा है। बहुत खुश हैं प्रोजेक्ट से। गुड जॉब टीम!",
        "वीकेंड पर डिप्लॉयमेंट है। शनिवार रात 11 बजे से शुरू करेंगे। तुम उपलब्ध हो?",
        "एपीरेजल साइकिल शुरू होने वाला है। सेल्फ-असेसमेंट फॉर्म भर लेना दिसंबर तक।",
        "कैंटीन में नया मेनू आया है। लंच पर चलें साथ में? पनीर टिक्का ट्राई करते हैं।",
        "स्टैंडअप मीटिंग 10 बजे है डेली अब। टाइमिंग बदल गई है, पहले 9:30 था।",
    ],
    "Bank Enquiry": [
        "हेलो, मुझे अकाउंट बैलेंस जानना है। अकाउंट नंबर 4523 में एंड होता है।",
        "फिक्स्ड डिपॉजिट स्कीम के बारे में मैसेज आया था। इंटरेस्ट रेट बताइए।",
        "क्रेडिट कार्ड के लिए अप्लाई करना है। कौन से दस्तावेज चाहिए और कितना समय लगेगा?",
        "चेक बुक खत्म हो गई है। नई इश्यू कर दीजिए प्लीज। अगले हफ्ते तक चाहिए।",
        "बेटी के लिए सेविंग्स अकाउंट खोलना है। अभी 18 साल की हुई है। क्या स्कीम हैं?",
        "आधार लिंक करना है बैंक अकाउंट से। ऑनलाइन प्रोसेजर क्या है?",
        "क्रेडिट कार्ड स्टेटमेंट में एक चार्ज नहीं समझ आ रहा। इन्वेस्टिगेट कर सकते हैं?",
        "फिक्स्ड डिपॉजिट मैच्योर हो गई है। रिन्यू करनी है या अमाउंट विड्रॉ करना है?",
        "नेट बैंकिंग का पासवर्ड रीसेट करना है। ब्रांच जाना पड़ेगा या ऑनलाइन हो जाएगा?",
        "मोबाइल नंबर अपडेट करना है बैंक अकाउंट में। क्या प्रोसेस है?",
        "पिछले 6 महीने का अकाउंट स्टेटमेंट चाहिए। ईमेल पर भेज सकते हैं?",
        "होम लोन के लिए प्री-अप्रूव्ड ऑफर आया है। इंटरेस्ट रेट की डिटेल्स जाननी हैं।",
        "डेबिट कार्ड एक्सपायर होने वाला है। नया कब मिलेगा? ऑटोमेटिक रिन्यूअल है क्या?",
        "पीपीएफ अकाउंट का बैलेंस चेक करना है। पासबुक अपडेट करवा सकता हूं क्या?",
        "लॉकर के लिए अप्लाई करना है ब्रांच में। अवेलेबिलिटी है क्या? चार्जेस कितने हैं?",
    ],
    "Shopping Conversation": [
        "फोन ऑर्डर किया है ऑनलाइन, कल आएगा। डिलीवरी पर्सन पहले कॉल करेगा।",
        "शुक्रवार से सेल शुरू है। सब 50% ऑफ है। शॉपिंग चलें ऑफिस के बाद?",
        "शर्ट रिटर्न की जो पिछले हफ्ते खरीदी थी। रिफंड 5-7 बिजनेस डेज में आएगा।",
        "नया वॉशिंग मशीन खरीदा। शनिवार सुबह इंस्टॉलेशन शेड्यूल है।",
        "स्टोर पर हूं। रेफ्रिजरेटर पर अच्छा ऑफर है। सैमसंग लूं या एलजी? बजट 30,000 रुपये।",
        "नए सोफे के 15,000 रुपये दिए। डिलीवरी 2 हफ्ते में होगी। क्वालिटी अच्छी है।",
        "बच्चों के स्कूल सप्लाइज खरीदने हैं। नोटबुक, पेन और नया स्कूल बैग।",
        "स्विगी से खाना ऑर्डर किया है। 40 मिनट में आएगा। तुम्हारे लिए भी ऑर्डर करूं?",
        "मिन्त्रा पर सेल लगी है। कुर्ता सेट खरीदना है। बजट 2,000 रुपये है। सुझाओ।",
        "किराने वाले का हिसाब करना है। 4,500 रुपये बाकी है। यूपीआई से भेज देती हूं।",
        "फ्लिपकार्ट से एसी ऑर्डर किया है। इंस्टॉलेशन फ्री है। बुधवार को आएगा।",
        "दीवाली की शॉपिंग शुरू करनी है। कपड़े और गिफ्ट दोनों खरीदने हैं।",
        "फार्मेसी से दवाई ले आओ। प्रिस्क्रिप्शन फोटो भेज रही हूं व्हाट्सएप पर।",
        "बच्चे के जूते टाइट हो गए हैं। वीकेंड पर नए खरीदने जाना है।",
        "इलेक्ट्रॉनिक्स स्टोर में प्रिंटर पर डिस्काउंट है। ऑफिस के लिए चाहिए था। 8,000 रुपये का है।",
    ],
    "Government Enquiry": [
        "पासपोर्ट ऑफिस गई थी आज। रिन्यूअल 15 वर्किंग डेज में होगा बोले।",
        "इनकम टैक्स रिटर्न फाइल करना है डेडलाइन से पहले। अच्छा सीए सुझाओ।",
        "ड्राइविंग लाइसेंस रिन्यू करवा लिया। स्मूथ प्रोसेस था। आरटीओ में एक घंटा लगा।",
        "प्रॉपर्टी टैक्स इस क्वार्टर का 8,000 रुपये है। ऑनलाइन पे कर दूंगी ड्यू डेट से पहले।",
        "राशन कार्ड के लिए अप्लाई किया था पिछले महीने। स्टेटस दिखाता है अंडर प्रोसेसिंग।",
        "पैन कार्ड आया है मेल में। अब फिक्स्ड डिपॉजिट अकाउंट खोल सकती हूं।",
        "वोटर आईडी में पता बदलवाना है। ऑनलाइन पोर्टल पर अप्लाई कर सकती हूं क्या?",
        "गैस कनेक्शन की सब्सिडी खाते में आ गई। 200 रुपये क्रेडिट हुआ है।",
        "ई-श्रम कार्ड बनवाया है ऑनलाइन। रजिस्ट्रेशन नंबर आ गया है।",
        "जन्म प्रमाण पत्र की कॉपी चाहिए। म्यूनिसिपल ऑफिस से मिलेगी या ऑनलाइन?",
        "पेंशन का स्टेटस चेक करना है। पोस्ट ऑफिस में जाकर पता करूंगी।",
        "आधार केंद्र 9 बजे से 5 बजे तक खुला है। कल जाऊंगी।",
        "राशन की दुकान पर आज चावल और दाल मिला। लाइन में 30 मिनट लगे।",
        "आज जल बोर्ड का बिल भरा ऑनलाइन। 850 रुपये था। रसीद सेव कर ली है।",
        "ड्राइविंग टेस्ट के लिए स्लॉट बुक किया है ऑनलाइन। अगले गुरुवार को अपॉइंटमेंट है।",
    ],
    "Emergency Conversation": [
        "किचन में छोटी सी आग लगी थी पर तुरंत बुझा दी। सब सुरक्षित हैं, चिंता मत करो।",
        "दादा जी के साथ अस्पताल में हूं। चक्कर आ गया था पर डॉक्टर ने बोला ठीक हैं अब।",
        "बिजली 3 घंटे से गई हुई है। इलेक्ट्रिसिटी बोर्ड को कॉल किया। शाम तक आएगी बोले।",
        "हाईवे पर माइनर कार एक्सीडेंट हुआ। कोई घायल नहीं है। इंश्योरेंस कंपनी को सूचित कर दिया।",
        "बाथरूम में पाइप फट गया। प्लंबर को बुलाया है, आ रहा है। मैंने वाल्व बंद कर दिया।",
        "बहुत बारिश की वजह से सड़क पर पानी भरा है। ड्राइव करना मुश्किल है। देर से आऊंगी।",
        "पार्क में गिर गई, पैर में हल्की मोच आई है। आइस लगा रही हूं। आने की जरूरत नहीं।",
        "बच्चे को बुखार आ गया है। पैरासीटामोल दी है। अगर कल तक नहीं उतरा तो डॉक्टर ले जाऊंगी।",
        "लिफ्ट 10 मिनट के लिए फंस गई थी। मेंटेनेंस ने फिक्स कर दिया। मैं ठीक हूं।",
        "गैस सिलेंडर का रेगुलेटर खराब हो गया। एजेंसी को कॉल किया है। कल नया भेजेंगे।",
        "बिजली का तार स्पार्क कर रहा था। इलेक्ट्रीशियन को बुलाया है। तब तक स्विच ऑफ है।",
        "पड़ोस में एम्बुलेंस आई थी। आंटी जी को अस्पताल ले गए। उनके बेटे को सूचित कर दिया।",
        "बच्चा साइकिल से गिर गया। घुटने पर चोट लगी है। फर्स्ट एड किट से बैंडेज कर दिया।",
        "रात को कोई दरवाजा नॉक कर रहा था। सिक्योरिटी गार्ड ने चेक किया, डिलीवरी बॉय था गलत फ्लोर पर।",
        "गीजर से पानी लीक हो रहा है। प्लंबर कल आएगा। तब तक बाल्टी से काम चला रहे हैं।",
    ],
}



# ====================================================================
# GENERATOR
# ====================================================================

def fill_template(template, vars_dict, rng):
    """Fill a template with random variable values."""
    result = template
    for key, values in vars_dict.items():
        placeholder = "{" + key + "}"
        while placeholder in result:
            result = result.replace(placeholder, rng.choice(values), 1)
    return result


def build_indicators_str(indicators):
    """Build pipe-delimited indicator string."""
    mapping = {
        "urgency": "urgency", "financial_request": "financial_request",
        "emotional_manipulation": "emotional_manipulation", "secrecy_request": "secrecy",
        "authority_impersonation": "authority_impersonation", "otp_request": "otp_request",
        "credential_request": "credential_request", "threat_detected": "threat",
    }
    active = [mapping[k] for k, v in indicators.items() if v == 1 and k in mapping]
    return "|".join(active) if active else "none"


def generate_scam_batch(category, data, count, rng):
    """Generate a batch of scam samples for one category."""
    samples = []
    seen = set()
    templates = data["templates"]
    vars_dict = data["vars"]
    max_attempts = count * 50

    for attempt in range(max_attempts):
        if len(samples) >= count:
            break
        tmpl = rng.choice(templates)
        text = fill_template(tmpl, vars_dict, rng)
        if text not in seen:
            seen.add(text)
            samples.append({
                "conversation_text": text,
                "label": "SCAM",
                "scam_category": category,
                "threat_level": data["threat_level"],
                **data["indicators"],
                "detected_indicators": build_indicators_str(data["indicators"]),
                "recommended_action": data["action"],
            })

    return samples


def generate_safe_batch(category, templates, count, rng):
    """Generate a batch of safe samples for one category."""
    samples = []
    seen = set()

    # First use all base templates
    for tmpl in templates:
        if len(samples) >= count:
            break
        if tmpl not in seen:
            seen.add(tmpl)
            samples.append(_make_safe_sample(tmpl))

    # Then generate variations
    prefixes = ["Haan, ", "Achha, ", "Sunno, ", "Btw, ", "Ek minute, ", "Aur haan, ",
                "Waise, ", "Oh, ", "Pata hai, ", "Arre, ", "Hey, ", "Bas, "]
    suffixes = [" Bata dena.", " Baad mein baat karte hain.", " Theek hai na?",
                " Chal, bye.", " Take care.", " Sab theek hai.", " Chalo, milte hain.",
                " Zyada tension mat le.", " Dekh lenge.", " Koi baat nahi.", " Done.",
                " Ok bye.", " Phir batati hoon."]

    max_attempts = count * 30
    for attempt in range(max_attempts):
        if len(samples) >= count:
            break
        base = rng.choice(templates)
        # Apply 1-2 variations
        variant = base
        r = rng.random()
        if r < 0.33:
            variant = rng.choice(prefixes) + base[0].lower() + base[1:]
        elif r < 0.66:
            variant = base + rng.choice(suffixes)
        else:
            variant = rng.choice(prefixes) + base[0].lower() + base[1:] + rng.choice(suffixes)

        if variant not in seen:
            seen.add(variant)
            samples.append(_make_safe_sample(variant))

    return samples


def _make_safe_sample(text):
    """Create a safe sample dict."""
    return {
        "conversation_text": text,
        "label": "SAFE",
        "scam_category": "None",
        "threat_level": "LOW",
        "urgency": 0, "financial_request": 0, "emotional_manipulation": 0,
        "secrecy_request": 0, "authority_impersonation": 0, "otp_request": 0,
        "credential_request": 0, "threat_detected": 0,
        "detected_indicators": "none",
        "recommended_action": SAFE_ACTION,
    }


def generate_dataset():
    """Generate the complete trilingual dataset (English + Hinglish + Devanagari Hindi)."""
    rng = random.Random(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)

    print("=" * 55, flush=True)
    print("    ASVD Demo - Synthetic Dataset Generator", flush=True)
    print("    Languages: English + Hinglish + Hindi (Devanagari)", flush=True)
    print("=" * 55, flush=True)
    print(flush=True)

    all_samples = []

    # --- English + Hinglish scam batches ---
    print("Generating SCAM conversations (English/Hinglish)...", flush=True)
    for cat_name, cat_data in SCAM_DATA.items():
        batch = generate_scam_batch(cat_name, cat_data, SCAM_PER_CATEGORY, rng)
        all_samples.extend(batch)
        print(f"  [{len(batch):>3}] {cat_name}", flush=True)

    # --- Hindi (Devanagari) scam batches ---
    HINDI_SCAM_PER_CATEGORY = 100
    print(f"\nGenerating SCAM conversations (Hindi Devanagari, {HINDI_SCAM_PER_CATEGORY}/category)...", flush=True)
    for cat_name, cat_data in SCAM_DATA_HINDI.items():
        batch = generate_scam_batch(cat_name, cat_data, HINDI_SCAM_PER_CATEGORY, rng)
        all_samples.extend(batch)
        print(f"  [{len(batch):>3}] {cat_name} (Hindi)", flush=True)

    scam_total = len(all_samples)
    print(f"  Total scam: {scam_total}", flush=True)

    # --- English + Hinglish safe batches ---
    print("\nGenerating SAFE conversations (English/Hinglish)...", flush=True)
    for cat_name, cat_templates in SAFE_DATA.items():
        batch = generate_safe_batch(cat_name, cat_templates, SAFE_PER_CATEGORY, rng)
        all_samples.extend(batch)
        print(f"  [{len(batch):>3}] {cat_name}", flush=True)

    # --- Hindi (Devanagari) safe batches ---
    HINDI_SAFE_PER_CATEGORY = 120
    print(f"\nGenerating SAFE conversations (Hindi Devanagari, {HINDI_SAFE_PER_CATEGORY}/category)...", flush=True)
    for cat_name, cat_templates in SAFE_DATA_HINDI.items():
        batch = generate_safe_batch(cat_name, cat_templates, HINDI_SAFE_PER_CATEGORY, rng)
        all_samples.extend(batch)
        print(f"  [{len(batch):>3}] {cat_name} (Hindi)", flush=True)

    safe_total = len(all_samples) - scam_total
    print(f"  Total safe: {safe_total}", flush=True)

    # Shuffle and assign IDs
    rng.shuffle(all_samples)
    for idx, sample in enumerate(all_samples, 1):
        sample["conversation_id"] = f"ASVD_{idx:06d}"

    # Create DataFrame
    columns = [
        "conversation_id", "conversation_text", "label", "scam_category",
        "threat_level", "urgency", "authority_impersonation",
        "financial_request", "otp_request", "credential_request",
        "threat_detected", "emotional_manipulation", "secrecy_request",
        "detected_indicators", "recommended_action",
    ]
    df = pd.DataFrame(all_samples, columns=columns)
    print(f"\nTotal dataset: {len(df)} samples", flush=True)
    return df



def split_dataset(df):
    """Split into train 70%, val 15%, test 15% with stratification."""
    train_df, temp_df = train_test_split(
        df, test_size=0.30, random_state=RANDOM_SEED, stratify=df["label"])
    val_df, test_df = train_test_split(
        temp_df, test_size=0.50, random_state=RANDOM_SEED, stratify=temp_df["label"])
    return train_df, val_df, test_df


def save_all(df, train_df, val_df, test_df):
    """Save all files."""
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8-sig")
    print(f"\n[OK] Saved: {OUTPUT_CSV}", flush=True)

    df.to_json(OUTPUT_JSON, orient="records", indent=2, force_ascii=False)
    print(f"[OK] Saved: {OUTPUT_JSON}", flush=True)

    for name, split_df in [("train", train_df), ("val", val_df), ("test", test_df)]:
        path = os.path.join(PROCESSED_DIR, f"{name}.csv")
        split_df.to_csv(path, index=False, encoding="utf-8-sig")
        print(f"[OK] Saved: {path}", flush=True)


def print_stats(df, train_df, val_df, test_df):
    """Print dataset statistics."""
    total = len(df)
    safe_n = (df["label"] == "SAFE").sum()
    scam_n = (df["label"] == "SCAM").sum()

    print("\n" + "=" * 55, flush=True)
    print("        ASVD Demo - Dataset Statistics", flush=True)
    print("=" * 55, flush=True)
    print(f"\n  Total Samples:     {total:>6,}", flush=True)
    print(f"  SAFE Samples:      {safe_n:>6,} ({safe_n/total:.1%})", flush=True)
    print(f"  SCAM Samples:      {scam_n:>6,} ({scam_n/total:.1%})", flush=True)

    print("\n  Scam Categories:", flush=True)
    scam_df = df[df["label"] == "SCAM"]
    for cat in sorted(scam_df["scam_category"].unique()):
        count = (scam_df["scam_category"] == cat).sum()
        print(f"    {cat:<30s} {count:>4}", flush=True)

    print(f"\n  Safe Conversations:  {safe_n}", flush=True)

    print("\n  Threat Levels:", flush=True)
    for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        count = (df["threat_level"] == level).sum()
        print(f"    {level:<12s} {count:>6,}", flush=True)

    print("\n  Train / Val / Test:", flush=True)
    print(f"    Train:  {len(train_df):>6,} ({len(train_df)/total:.1%})", flush=True)
    print(f"    Val:    {len(val_df):>6,} ({len(val_df)/total:.1%})", flush=True)
    print(f"    Test:   {len(test_df):>6,} ({len(test_df)/total:.1%})", flush=True)

    print("\n  Example Conversations:", flush=True)
    print("  " + "-" * 53, flush=True)
    examples = pd.concat([
        df[df["label"] == "SCAM"].sample(3, random_state=RANDOM_SEED),
        df[df["label"] == "SAFE"].sample(2, random_state=RANDOM_SEED),
    ])
    for _, row in examples.iterrows():
        print(f"\n  ID:       {row['conversation_id']}", flush=True)
        print(f"  Label:    {row['label']} | {row['scam_category']}", flush=True)
        print(f"  Threat:   {row['threat_level']}", flush=True)
        text = str(row["conversation_text"])[:120]
        print(f"  Text:     {text}...", flush=True)
        print(f"  Flags:    {row['detected_indicators']}", flush=True)
        print("  " + "-" * 53, flush=True)

    print("\n" + "=" * 55, flush=True)
    print("  Dataset generation complete!", flush=True)
    print("=" * 55 + "\n", flush=True)


# ====================================================================
# MAIN
# ====================================================================

def main():
    parser = argparse.ArgumentParser(description="ASVD Demo - Dataset Generator")
    parser.add_argument("--stats", action="store_true", help="Show stats of existing dataset")
    args = parser.parse_args()

    if args.stats:
        if not os.path.exists(OUTPUT_CSV):
            print("ERROR: Dataset not found. Run without --stats first.")
            sys.exit(1)
        df = pd.read_csv(OUTPUT_CSV, encoding="utf-8-sig")
        train_df = pd.read_csv(os.path.join(PROCESSED_DIR, "train.csv"), encoding="utf-8-sig")
        val_df = pd.read_csv(os.path.join(PROCESSED_DIR, "val.csv"), encoding="utf-8-sig")
        test_df = pd.read_csv(os.path.join(PROCESSED_DIR, "test.csv"), encoding="utf-8-sig")
        print_stats(df, train_df, val_df, test_df)
    else:
        df = generate_dataset()
        train_df, val_df, test_df = split_dataset(df)
        save_all(df, train_df, val_df, test_df)
        print_stats(df, train_df, val_df, test_df)

        # Auto-retrain the ML classifier with the new data
        try:
            sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
            from backend.app.model.train_classifier import run_training

            print()
            print("=" * 55)
            print("    ASVD Demo - Auto-Retraining ML Classifier")
            print("=" * 55)
            print()

            metrics = run_training()

            print(f"  Accuracy:   {metrics['accuracy']:.4f}")
            print(f"  Precision:  {metrics['precision']:.4f}")
            print(f"  Recall:     {metrics['recall']:.4f}")
            print(f"  F1 Score:   {metrics['f1']:.4f}")
            print()
            print("  [OK] Model retrained successfully!")
            print("=" * 55)
        except Exception as e:
            print(f"\n  [WARN] Auto-retrain skipped: {e}")
            print("  Run manually: python -m backend.app.model.train_classifier")


if __name__ == "__main__":
    main()
