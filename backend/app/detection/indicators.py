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
    
    # -----------------------------------------------------------------------
    # COMPREHENSIVE DEVANAGARI HINDI → HINGLISH TRANSLITERATION
    # Covers all scam indicator categories for STT hi-IN output
    # -----------------------------------------------------------------------

    # --- OTP / Credentials ---
    (r"ओटीपी", "otp"),
    (r"पासवर्ड|पिन\s*नंबर|पिन", "password pin"),
    (r"सीवीवी|सी\.वी\.वी", "cvv"),
    (r"बताइए|बताओ|बताएं|बता\s*दो|दीजिए|दे\s*दो|शेयर\s*करें|शेयर\s*करो", "batao"),
    (r"नेट\s*बैंकिंग|इंटरनेट\s*बैंकिंग", "net banking"),
    (r"यूजर\s*आईडी|लॉगिन\s*आईडी", "user id"),

    # --- Financial / Money ---
    (r"रुपये|रुपए|रुपया", "rs"),
    (r"पैसे|पैसा", "paisa"),
    (r"लाख", "lakh"),
    (r"करोड़|करोड", "crore"),
    (r"हजार", "hazar"),
    (r"भेज\s*दो|भेजो|भेजें|भेज\s*दीजिए|भेज\s*दे", "transfer bhej do"),
    (r"ट्रांसफर\s*करो|ट्रांसफर\s*करें|ट्रांसफर\s*कर\s*दो", "transfer karo"),
    (r"जमा\s*करो|जमा\s*करें|जमा\s*कर\s*दो", "transfer karo"),
    (r"पेमेंट\s*करो|पेमेंट\s*कर\s*दो", "payment karo"),
    (r"यूपीआई|यू\.पी\.आई", "upi"),
    (r"गूगल\s*पे", "google pay"),
    (r"फोन\s*पे", "phonepe"),
    (r"पेटीएम", "paytm"),
    (r"अकाउंट\s*नंबर", "account number"),
    (r"अकाउंट|खाता", "account"),
    (r"ब्लॉक\s*हो\s*जाएगा|ब्लॉक\s*हो\s*जायेगा|बंद\s*हो\s*जाएगा|बंद\s*हो\s*जायेगा|फ्रीज\s*हो\s*जाएगा", "account block ho jayega"),
    (r"ब्लॉक|फ्रीज|सील|बंद\s*करें|बंद\s*कर\s*दें", "block freeze"),
    (r"फिरौती|रैनसम", "firauti"),
    (r"जुर्माना|फाइन\s*भरो|फाइन\s*दो", "fine bharo"),
    (r"वेरिफिकेशन\s*फीस|प्रोसेसिंग\s*फीस|क्लीयरेंस\s*फीस", "verification fee"),
    (r"डबल\s*पैसा|पैसा\s*दोगुना", "double money"),

    # --- Urgency ---
    (r"तुरंत|तुरन्त", "turant"),
    (r"जल्दी|जल्द", "jaldi"),
    (r"अभी\s*के\s*अभी|अभी\s*तुरंत", "abhi ke abhi"),
    (r"अभी", "abhi"),
    (r"फौरन|फ़ौरन", "turant"),
    (r"देर\s*मत\s*करो|देरी\s*मत\s*करो", "jaldi karo"),
    (r"आज\s*ही|आज\s*रात\s*तक", "aaj hi"),
    (r"एक\s*घंटे\s*में|दो\s*घंटे\s*में|\d+\s*घंटे\s*में", "ek ghante mein"),
    (r"\d+\s*मिनट\s*में", "minute mein"),
    (r"आखिरी\s*मौका|अंतिम\s*चेतावनी|लास्ट\s*वॉर्निंग", "urgent last warning"),

    # --- Authority / Impersonation ---
    (r"एसबीआई|भारतीय\s*स्टेट\s*बैंक", "sbi bank"),
    (r"एचडीएफसी\s*बैंक|एचडीएफसी", "hdfc bank"),
    (r"आईसीआईसीआई|आईसीआईसीआई\s*बैंक", "icici bank"),
    (r"बैंक\s*से\s*बोल\s*रहा\s*हूं|बैंक\s*की\s*तरफ\s*से\s*कॉल|बैंक\s*से\s*कॉल", "bank se call"),
    (r"बैंक\s*का\s*अधिकारी|बैंक\s*ऑफिसर|बैंक\s*का\s*प्रतिनिधि", "bank officer"),
    (r"धोखाधड़ी\s*विभाग|फ्रॉड\s*प्रिवेंशन\s*टीम|सिक्योरिटी\s*टीम", "fraud prevention team"),
    (r"पुलिस", "police"),
    (r"सीबीआई|सी\.बी\.आई", "cbi"),
    (r"इंस्पेक्टर|सब-इंस्पेक्टर|एसपी|डीएसपी", "inspector"),
    (r"थाना|पुलिस\s*स्टेशन", "police station"),
    (r"साइबर\s*क्राइम|साइबर\s*सेल", "cyber crime"),
    (r"आरबीआई|भारतीय\s*रिजर्व\s*बैंक|आर\.बी\.आई", "rbi"),
    (r"इनकम\s*टैक्स|आयकर\s*विभाग", "income tax department"),
    (r"ईडी|प्रवर्तन\s*निदेशालय", "ed enforcement"),
    (r"कस्टम\s*विभाग|कस्टम्स", "customs department"),
    (r"ट्राई|टेलीकॉम\s*विभाग", "trai telecom"),
    (r"मंत्रालय", "ministry"),

    # --- Threats / Legal ---
    (r"गिरफ्तार\s*हो\s*जाएंगे|गिरफ्तार\s*कर\s*लेंगे|गिरफ्तारी", "arrest"),
    (r"गिरफ्तार", "arrest"),
    (r"जेल\s*होगी|जेल\s*जाएंगे|जेल\s*में\s*डाल\s*देंगे", "jail"),
    (r"जेल", "jail"),
    (r"वारंट\s*जारी\s*हो\s*गया|वारंट\s*है\s*आपके\s*नाम", "warrant"),
    (r"वारंट", "warrant"),
    (r"एफआईआर\s*दर्ज|एफआईआर\s*हुआ|एफआईआर\s*है", "fir"),
    (r"एफआईआर|एफ\.आई\.आर", "fir"),
    (r"कानूनी\s*कार्रवाई|लीगल\s*एक्शन", "legal action"),
    (r"मुकदमा|केस\s*दर्ज", "case file"),
    (r"मार\s*दूंगा|मार\s*डालूंगा|जान\s*से\s*मार|जान\s*ले\s*लूंगा", "marunga jaan se"),
    (r"किडनैप|अपहरण|अगवा|उठवा\s*लिया", "kidnap"),
    (r"ब्लैकमेल|ब्लैकमेल\s*करूंगा", "blackmail"),
    (r"वीडियो\s*वायरल\s*करूंगा|फोटो\s*वायरल|सबको\s*दिखाऊंगा", "video viral expose"),
    (r"संपत्ति\s*जब्त|सम्पत्ति\s*सीज|प्रॉपर्टी\s*सीज", "asset seizure"),

    # --- Secrecy / Isolation ---
    (r"किसी\s*को\s*मत\s*बताना|किसी\s*को\s*न\s*बताएं|किसी\s*को\s*मत\s*बताएं", "kisi ko mat batana"),
    (r"किसी\s*को\s*मत\s*बताओ|बताना\s*नहीं\s*है|मत\s*बताना", "kisi ko mat batana"),
    (r"पापा\s*को\s*मत\s*बताना|पापा\s*को\s*मत\s*बताओ", "papa ko mat batana"),
    (r"मम्मी\s*को\s*मत\s*बताना|माँ\s*को\s*मत\s*बताना|मम्मी\s*को\s*मत\s*बताओ", "mummy ko mat batana"),
    (r"परिवार\s*को\s*मत\s*बताना|घरवालों\s*को\s*मत\s*बताना", "family ko mat batana"),
    (r"वकील\s*को\s*मत\s*बताना|पुलिस\s*को\s*मत\s*बताना", "lawyer ko mat batana"),
    (r"गुप्त|सीक्रेट|गोपनीय|बीच\s*में\s*रखो", "secret confidential"),
    (r"अकेले\s*बात\s*करो|अकेले\s*में\s*बात", "akele baat karo"),

    # --- Emotional Manipulation / Family ---
    (r"मेरा\s*बेटा|मेरी\s*बेटी|आपका\s*बेटा|आपकी\s*बेटी", "bete family member"),
    (r"बेटा|बेटी|बच्चा|बच्चे", "bete family member"),
    (r"मम्मी|माँ|माता\s*जी", "mummy"),
    (r"पापा|पिता\s*जी", "papa"),
    (r"भाई|बड़े\s*भाई|भैया", "bhai"),
    (r"दीदी|बहन", "sister"),
    (r"परिवार|घरवाले", "family"),
    (r"अस्पताल|हॉस्पिटल", "hospital"),
    (r"एडमिट\s*है|भर्ती\s*है|एडमिट\s*हो\s*गया|भर्ती\s*हो\s*गया", "admit hai"),
    (r"एक्सीडेंट\s*हो\s*गया|दुर्घटना|टक्कर\s*हो\s*गई|चोट\s*लगी", "accident ho gaya"),
    (r"तबीयत\s*खराब|तबियत\s*खराब|बहुत\s*बीमार|हालत\s*गंभीर|सीरियस\s*है", "tabiyat kharab"),
    (r"ऑपरेशन\s*चाहिए|सर्जरी\s*चाहिए|ऑपरेशन\s*होगा", "operation chahiye"),
    (r"डॉक्टर|इलाज|उपचार", "doctor"),
    (r"आईसीयू|आइसोलेशन", "icu"),
    (r"मदद\s*करो|मदद\s*कीजिए|बचाओ|प्लीज\s*मदद", "help karo bachao"),
    (r"बहुत\s*परेशानी\s*में|मुसीबत\s*में\s*हूं|फंसा\s*हूं|फंसी\s*हूं", "bahut pareshani mein"),
    (r"सिर्फ\s*तुम|सिर्फ\s*आप|केवल\s*आप", "sirf tum"),
    (r"विश्वास\s*करो|यकीन\s*करो|भरोसा\s*करो", "vishwas karo"),
    (r"डर\s*लग\s*रहा|डरा\s*हुआ|घबरा\s*गया", "darr scared"),
    (r"गारंटी\s*है|गारंटीड|पक्का\s*मुनाफा", "guaranteed profit"),
    (r"पैसा\s*दोगुना|दोगुना\s*रिटर्न|100%\s*सेफ", "double money guaranteed"),

    # --- Credentials, Passwords & OTP Accents (Roman/STT variations) ---
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
