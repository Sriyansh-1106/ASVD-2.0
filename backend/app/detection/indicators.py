"""ASVD Demo - Social Engineering Indicator Detector.

Detects scam indicators in conversation text using keyword patterns
and context-aware rules. Supports English, Hindi, and Hinglish.

Usage:
    from backend.app.detection.indicators import detect_indicators
    result = detect_indicators("Turant Rs 50,000 bhej do")

Returns:
    dict with boolean flags for each indicator type,
    a list of detected indicators, and the count.
"""

import re


# ====================================================================
# INDICATOR PATTERNS
# Each pattern group has:
#   - "positive": phrases that indicate the scam signal
#   - "negative": context patterns that cancel out false positives
# ====================================================================

# ====================================================================
# COMPREHENSIVE INDIAN ACCENT & HINGLISH PHONETIC NORMALIZER
# ====================================================================

PHONETIC_REPLACEMENTS = [
    # --- Urgency & Accent variations ---
    (r"\b(argent|arjent|urjent|aarjent|ergent|arjant)\b", "urgent"),
    (r"\b(argently|urjently|arjtly)\b", "urgently"),
    (r"\b(jldi|jalde|jaldee)\b", "jaldi"),
    (r"\b(trunt|turnt)\b", "turant"),
    (r"\b(chahie|chaheye|chahye|chaahiye)\b", "chahiye"),
    (r"\b(jaroorat|zaroorat|jarurt|zrurat)\b", "jarurat"),
    
    # --- Threats, Kidnapping & Violence ---
    (r"\b(kidnaap|kidnapig|kidnaaping|kidnp|kidnaped)\b", "kidnap"),
    (r"\b(uthva|utha|uthwa)\s*(liya|lia|lenge|luga)\b", "kidnap kar liya"),
    (r"\b(mar duga|maar duga|maar dunga|mar dalunga|maruga|marenge)\b", "marunga"),
    (r"\b(jan se|jaan se)\b", "jaan se"),
    (r"\b(chodunga nahi|chhoduga nahi|choduga nhi)\b", "chhodunga nahi"),
    (r"\b(firouti|firawti|ransom|ransem)\b", "firauti"),
    
    # --- Authority & Police Accent variations ---
    (r"\b(pulis|pulees|polees|polic)\b", "police"),
    (r"\b(insepctor|inspektar|ispector|insepector)\b", "inspector"),
    (r"\b(sayber|syber|seiber)\s*(crime|kraym|kraim)?\b", "cyber crime"),
    (r"\b(si\s*bi\s*ai|c\s*bi\s*i|c\.b\.i|cbi)\b", "cbi"),
    (r"\b(ar\s*bi\s*ai|r\s*b\s*i|rbi)\b", "rbi"),
    (r"\b(kourt|kot|kort)\b", "court"),
    (r"\b(varent|varrant|warent|warrant)\b", "warrant"),
    (r"\b(arest|errest|arst)\b", "arrest"),
    (r"\b(jel|jale)\b", "jail"),
    (r"\b(f\s*i\s*r|eff\s*aye\s*aar)\b", "fir"),

    # --- Financial & Money Accents ---
    (r"₹\s*", "rs "),
    (r"\b(peisa|paise|pesa|rupiya|rupee|rupia|rupye)\b", "paisa"),
    (r"\b(ekaunt|akount|acount|acc)\b", "account"),
    (r"\b(kard|kardh)\b", "card"),
    (r"\b(tranfar|trasfer|tranzfer|bhej|bej|bhejo|bejo)\b", "transfer"),
    (r"\b(gugle\s*pe|g\s*pay|gpay)\b", "google pay"),
    (r"\b(fon\s*pe|phone\s*pe|fonpe|phonepe)\b", "phonepe"),
    (r"\b(petiem|paytam|paytm)\b", "paytm"),
    (r"\b(lakh|lakhs|lakh rupees|lac|lacs)\b", "lakh"),
    (r"\b(krore|crore|crores)\b", "crore"),
    (r"\b(hazar|hazaar|thousand)\b", "hazar"),
    
    # --- Devanagari Hindi to English/Hinglish Transliteration ---
    (r"किडनैप|अपहरण|अगवा|उठवा", "kidnap"),
    (r"मारूंगा|मार दूंगा|मार डालूंगा|जान से|खत्म कर", "marunga jaan se"),
    (r"ओटीपी", "otp"),
    (r"पासवर्ड|पिन|सीवीवी", "password pin cvv"),
    (r"रुपये|रुपए|रुपया|पैसे|लाख|करोड़|हजार", "rs lakh"),
    (r"तुरंत|जल्दी|अर्जेंट|अभी के अभी", "urgent turant"),
    (r"पुलिस|सीबीआई|इंस्पेक्टर|कस्टम|थाना", "police cbi inspector"),
    (r"इनकम टैक्स|टैक्स डिपार्टमेंट|क्राइम ब्रांच|आरबीआई", "income tax department cyber crime rbi"),
    (r"अस्पताल|हॉस्पिटल|तबीयत|एडमिट|एक्सीडेंट|डॉक्टर|ऑपरेशन|सर्जरी|इलाज", "hospital admit tabiyat accident doctor"),
    (r"अकाउंट|खाता|ब्लॉक|फ्रीज|सील", "account block freeze"),
    (r"ट्रांसफर|भेज दो|जमा|पेमेंट", "transfer"),
    (r"गिरफ्तार|जेल|वारंट|केस|एफआईआर", "arrest jail warrant fir"),
    (r"किसी को मत बताना|सीक्रेट|गुप्त", "kisi ko mat batana"),
    (r"फिरौती|रैनसम", "firauti"),
    (r"बेटे|बेटी|बच्चे|परिवार", "bete family member"),

    # --- Credentials, Passwords & OTP Accents ---
    (r"\b(otipi|o\s*t\s*p|odipi|ooteepee)\b", "otp"),
    (r"\b(passward|pasward|pasword|passwrd)\b", "password"),
    (r"\b(si\s*vi\s*vi|c\s*v\s*v|cv)\b", "cvv"),
    (r"\b(masseg|mesage|massej|massege|msg)\b", "message"),
    (r"\b(varification|varify|verifay)\b", "verification"),
    (r"\b(bta|btao|btayein|batna)\b", "batao"),
    (r"\b(ksiko|kisko|kisi\s*ko)\s*(mat|nhi|nahi)\b", "kisi ko mat"),
]

def normalize_speech_text(text: str) -> str:
    """Normalize common Indian accent, Hinglish, and Speech-to-Text variations."""
    if not text:
        return ""
    t = text.lower().strip()
    for pattern, repl in PHONETIC_REPLACEMENTS:
        t = re.sub(pattern, repl, t, flags=re.IGNORECASE)
    return t


# ====================================================================
# INDICATOR PATTERNS
# ====================================================================

URGENCY_PATTERNS = {
    "positive": [
        r"\bturant\b", r"\bjaldi\b", r"\babhi\b", r"\bimmediately\b",
        r"\burgent\b", r"\burgently\b", r"\bargent\b", r"\burjent\b", r"\barjent\b",
        r"\bright now\b", r"\bdon'?t delay\b", r"\babhi ke abhi\b",
        r"\bwaqt nahi\b", r"\btime nahi\b", r"\bwithin \d+ (minute|hour|ghante)\b",
        r"\btoday only\b", r"\baaj hi\b", r"\baaj ke liye\b",
        r"\bjaldi karo\b", r"\bhurry\b", r"\bact now\b",
        r"\bexpire\b", r"\bdeadline\b", r"\btimer\b",
        r"\bek ghante mein\b", r"\b\d+ ghante\b", r"\b\d+ minute mein\b",
        r"\bchahiye\b.*\b(turant|jaldi|urgent|abhi)\b",
        r"\burgent\b.*\b(chahiye|chahie|hai)\b",
    ],
    "negative": [
        r"\bjaldi aa jaana\b", r"\bjaldi ghar\b", r"\bjaldi nikalenge\b",
    ],
}

FINANCIAL_PATTERNS = {
    "positive": [
        r"\bbhej do\b", r"\btransfer\b", r"\bsend money\b", r"\bsend the money\b",
        r"\bpaisa\b.*\b(bhej|de|do|transfer|chahiye|jarurat)\b",
        r"\b(paise|rupaye|rupees|amount)\b.*\b(bhej|transfer|pay|do|chahiye|jarurat)\b",
        r"₹\s*[\d,]+", r"\brs\.?\s*[\d,]+\b", r"\b[\d,]{4,}\s*(rupees|rs|paisa|chahiye|ki jarurat)\b",
        r"\brunpees?\b", r"\b(pay|payment)\s+(kar|karo|karein|karna)\b",
        r"\bprocessing fee\b", r"\bregistration fee\b", r"\bsettlement\b",
        r"\bdeposit\b.*\b(bhej|karo|karein)\b", r"\bfine\b.*\b(bharo|do|pay)\b",
        r"\bverification (fee|charges)\b", r"\bclearance fee\b",
        r"\bupi\b.*\b(bhej|se|pe)\b.*\b(bhej|transfer|do)\b",
        r"\baccount (number|mein)\b.*\b(bhej|transfer|jama)\b",
        r"\b(500000|100000|200000|50000|lakh|lakhs|crore|hazar)\b.*\b(chahiye|bhej|de|do|jarurat)\b",
        r"\b(firauti|ransom|chanda|bhatta)\b",
    ],
    "negative": [
        r"\bsalary credit\b", r"\bsalary aa gayi\b", r"\bbill bhara\b",
        r"\bfee (due|hai|is)\b(?!.*\b(do|bhej|pay|karo)\b)",
        r"\brefund\b.*\b(aa gaya|mil gaya|aayega)\b",
        r"\bkhushi\b", r"\bkhush\b",
    ],
}

OTP_PATTERNS = {
    "positive": [
        r"\botp\b", r"\bone.?time.?password\b", r"\bverification code\b",
        r"\b6.?digit code\b", r"\bcode\b.*\b(bata|share|tell|dijiye|batao|batayein)\b",
        r"\botp\b.*\b(bata|share|tell|dijiye|batao|batayein)\b",
        r"\bcode aaya\b", r"\bcode aa gaya\b",
    ],
    "negative": [],
}

CREDENTIAL_PATTERNS = {
    "positive": [
        r"\b(atm\s*)?pin\b.*\b(bata|share|tell|dijiye|batao|batayein)\b",
        r"\bcvv\b", r"\bcard number\b", r"\b16.?digit\b",
        r"\bpassword\b.*\b(share|bata|tell|dijiye|batao|batayein|do)\b",
        r"\bnet banking\b.*\b(password|credentials|login)\b",
        r"\buser\s*id\b.*\b(password|bata|share)\b",
        r"\bexpiry date\b.*\b(bata|share|tell)\b",
        r"\bcard details\b", r"\bcard ke\b.*\b(number|details)\b",
        r"\bupi pin\b",
    ],
    "negative": [
        r"\bpassword yaad rakh\b", r"\bpassword mat batana\b",
        r"\bpassword change\b", r"\bpassword reset\b",
    ],
}

AUTHORITY_PATTERNS = {
    "positive": [
        r"\b(inspector|sub.?inspector|acp|dcp|commissioner)\b",
        r"\bcyber\s*crime\b", r"\bpolice\b.*\b(department|headquarters|se call|bol raha)\b",
        r"\b(sbi|hdfc|icici|axis|pnb|kotak|yes bank|indusind)\b.*\b(se call|bol raha|fraud|security|team)\b",
        r"\bfraud prevention team\b", r"\bsecurity department\b",
        r"\b(income tax|customs|trai|rbi|ministry)\b.*\b(department|se call|se bol|notice)\b",
        r"\btechnical team\b.*\b(bol raha|hai|from)\b",
        r"\bverification officer\b", r"\bcompliance team\b",
        r"\bbank\b.*\b(se call|bol raha|ka officer|ka team|fraud team)\b",
    ],
    "negative": [
        r"\bbank jaana\b", r"\bbank mein\b.*\b(jaana|gaya|gayi|jaaungi|jaunga)\b",
        r"\bbank\b.*\b(account kholne|cheque deposit|balance)\b",
        r"\bpolice station ke paas\b", r"\bpolice ko bulaya\b",
        r"\bcourt ke paas\b",
    ],
}

THREAT_PATTERNS = {
    "positive": [
        # Kidnapping & Hostage
        r"\b(kidnap|kidnapping|agva|uthwa liya|uthwa lenge|kabze mein)\b",
        r"\b(bete|beti|bacche|bache|family|gharwale|brother|sister)\b.*\b(kidnap|uthwa|kabze)\b",
        r"\bkidnap\b.*\b(kar liya|kar lenge|hai)\b",

        # Physical Violence & Murder Threats
        r"\b(marunga|maar dunga|maar dalunga|mar dalenge|khatam kar dunga|goli mar dunga|jaan se|chhodunga nahi)\b",
        r"\b(bahut marunga|jaan se mar|laash)\b",
        r"\b(harm|kill|murder|dead|torture|shoot|beat)\b",
        r"\b(mar jayega|mar jayenge|jaan khatre mein|serious halat|bach nahi payega)\b",

        # Legal & Arrest Threats
        r"\barrest\b", r"\bjail\b", r"\bwarrant\b",
        r"\blegal action\b", r"\bcourt (mein|case|order)\b",
        r"\bcase file\b", r"\bfir\b", r"\bcriminal\b.*\b(case|charges)\b",
        r"\baccount\b.*\b(block|freeze|suspend|lock)\b.*\b(ho jayega|kar denge|permanently)\b",
        r"\bpassport\b.*\b(cancel|suspend)\b",

        # Blackmail & Extortion
        r"\b(blackmail|extortion|firauti|bhatta)\b",
        r"\bexpose\b", r"\bpublish\b", r"\brelease\b.*\b(publicly|online|social media)\b",
        r"\b(video|photos?|pics?)\b.*\b(viral|leak|share|send)\b",
        r"\bcontacts ko bhej\b", r"\bsab ko bhej\b",
        r"\bconsequences\b", r"\bpolice aayegi\b", r"\bofficers will come\b",
        r"\basset seizure\b",
    ],
    "negative": [
        r"\bcourt ke paas\b.*\b(restaurant|dukaan|khula)\b",
        r"\bblock nahi\b", r"\bblock mat\b",
    ],
}

SECRECY_PATTERNS = {
    "positive": [
        r"\bmat batana\b", r"\bmat bolna\b", r"\bmat bata\b",
        r"\bdon'?t tell\b", r"\bdon'?t contact\b", r"\bdon'?t involve\b",
        r"\bkisi ko (mat|nahi)\b", r"\bkeep (it )?(secret|private|between us)\b",
        r"\bkeep this\b.*\b(private|confidential|secret)\b",
        r"\bfamily ko mat\b", r"\bpapa ko mat\b", r"\bmummy ko mat\b",
        r"\bgroup mein mat\b", r"\blawyer ko mat\b",
        r"\bpolice ko mat\b", r"\bpolice ko bataya\b",
        r"\bhamare beech\b", r"\bbetween us\b",
        r"\bconfidential\b", r"\bclassified\b",
    ],
    "negative": [],
}

EMOTIONAL_PATTERNS = {
    "positive": [
        r"\bplease help\b", r"\bhelp (karo|kar do|karein|me)\b",
        r"\bbegging\b", r"\bbheed\b", r"\bminnat\b",
        r"\bdarr\b", r"\bscared\b", r"\bI'?m scared\b",
        r"\btrouble\b.*\b(please|help)\b", r"\bpareshani\b",
        r"\bkoi aur nahi\b", r"\bno one else\b", r"\bnobody else\b",
        r"\bsirf tum\b", r"\bonly you\b",
        r"\btrust me\b", r"\bplease trust\b", r"\bvishwas karo\b",
        r"\bbahut zaroorat\b", r"\bdesperate\b",
        r"\bI am in\b.*\b(trouble|danger)\b",
        r"\b(bete|beti|baccha)\b.*\b(bachao|chhod do|khatre mein)\b",
        # Medical, Accident & Hospital Emergency Extortion / Scam Vectors
        r"\b(hospital|haspatal)\b.*\b(admit|admit hai|serious|emergency|operation|surgery|doctor)\b",
        r"\b(tabiyat|tabiat)\b.*\b(kharab|bahut kharab|serious|critical|kharab hai)\b",
        r"\b(accident|accident ho gaya|takkar|chot lagi|ghayal)\b",
        r"\b(operation|surgery|blood|icu|oxygen|treatment)\b.*\b(chahiye|paise|urgent|turant|admit|karna hai)\b",
        r"\b(papa|mummy|bhai|sister|dost|uncle|aunty)\b.*\b(hospital|admit|serious|tabiyat|accident)\b",
        r"\b(admit hai|admit karwaya|admit kiya)\b",
        r"\bguaranteed\b.*\b(return|profit|income)\b",
        r"\bdouble\b.*\b(money|paise|paisa)\b",
        r"\b100%\s*(safe|legal|guaranteed)\b",
        r"\bno risk\b", r"\bzero risk\b",
    ],
    "negative": [
        r"\bmovie\b.*\b(mazaa|achhi|achha|great)\b",
        r"\bkhushi\b", r"\bkhush\b", r"\bbahut achha\b",
        r"\bparty\b", r"\bcelebrat\b",
    ],
}


# ====================================================================
# DETECTOR FUNCTION
# ====================================================================

def _check_patterns(text_lower: str, pattern_group: dict) -> bool:
    """Check if text matches positive patterns and doesn't match negatives."""
    # Check negative patterns first (context cancellers)
    for pattern in pattern_group.get("negative", []):
        if re.search(pattern, text_lower):
            return False

    # Check positive patterns
    for pattern in pattern_group["positive"]:
        if re.search(pattern, text_lower):
            return True

    return False


def detect_indicators(text: str) -> dict:
    """Detect social engineering indicators in conversation text.

    Args:
        text: Conversation text in English, Hindi, or Hinglish.

    Returns:
        dict with:
            - Boolean flags for each indicator type
            - detected_list: list of detected indicator names
            - indicator_count: number of indicators detected
    """
    if not text or not text.strip():
        return {
            "urgency": False,
            "financial_request": False,
            "otp_request": False,
            "credential_request": False,
            "authority_impersonation": False,
            "threat_detected": False,
            "secrecy_request": False,
            "emotional_manipulation": False,
            "detected_list": [],
            "indicator_count": 0,
        }

    text_norm = normalize_speech_text(text)
    text_lower = text_norm.lower().strip()

    # Check each indicator
    indicators = {
        "urgency": _check_patterns(text_lower, URGENCY_PATTERNS),
        "financial_request": _check_patterns(text_lower, FINANCIAL_PATTERNS),
        "otp_request": _check_patterns(text_lower, OTP_PATTERNS),
        "credential_request": _check_patterns(text_lower, CREDENTIAL_PATTERNS),
        "authority_impersonation": _check_patterns(text_lower, AUTHORITY_PATTERNS),
        "threat_detected": _check_patterns(text_lower, THREAT_PATTERNS),
        "secrecy_request": _check_patterns(text_lower, SECRECY_PATTERNS),
        "emotional_manipulation": _check_patterns(text_lower, EMOTIONAL_PATTERNS),
    }

    # Build detected list
    detected = [name for name, flagged in indicators.items() if flagged]

    return {
        **indicators,
        "detected_list": detected,
        "indicator_count": len(detected),
    }
