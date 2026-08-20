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
    """Generate the complete dataset in small batches."""
    rng = random.Random(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)

    print("=" * 55, flush=True)
    print("    ASVD Demo - Synthetic Dataset Generator", flush=True)
    print("=" * 55, flush=True)
    print(flush=True)

    all_samples = []

    # Generate scam samples batch by batch
    print("Generating SCAM conversations...", flush=True)
    for cat_name, cat_data in SCAM_DATA.items():
        batch = generate_scam_batch(cat_name, cat_data, SCAM_PER_CATEGORY, rng)
        all_samples.extend(batch)
        print(f"  [{len(batch):>3}] {cat_name}", flush=True)

    scam_total = len(all_samples)
    print(f"  Total scam: {scam_total}", flush=True)

    # Generate safe samples batch by batch
    print("\nGenerating SAFE conversations...", flush=True)
    for cat_name, cat_templates in SAFE_DATA.items():
        batch = generate_safe_batch(cat_name, cat_templates, SAFE_PER_CATEGORY, rng)
        all_samples.extend(batch)
        print(f"  [{len(batch):>3}] {cat_name}", flush=True)

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
