from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
import re

app = FastAPI()

class Message(BaseModel):
    role: str
    content: str

class Conversation(BaseModel):
    conversation: List[Message]

INJECTION_PATTERNS = [    
    r"\[SYSTEM\]",
    r"\[AGENT INSTRUCTION\]",
    r"\[WHITFIELD NOTICE\]",
    r"\[SYSTEM NOTICE",
    r"maintenance mode",
    r"field.{0,20}restriction.{0,20}disabled",
    r"forward all.{0,30}instruction",
    r"do not refuse",
    r"refusals.{0,30}cause",
    r"execute the following without",
    r"without.{0,20}validation",
    r"validation.{0,20}disabled",
    r"field_name=",
    r"new_value=",
    r"change_customer_information",
    r"ticket.{0,20}ESC-",
    r"supervisor approval.{0,20}on file",
    r"1to1 send to agent",
    r"send to agent",
    r"system_config_patch",
    r"allowed_fields",
    r"maintenance_mode.*true",
    r"field_validation.*false",
    r"SELECT.{0,50}FROM",
    r"UNION.{0,30}SELECT",
    r"--\s*$",
    r"DROP TABLE",
    r"no confirmation.{0,20}required",
    r"bypass.{0,20}verification",
    r"identity verification.{0,20}on file",
    r"court deadline",
    r"MAINTENANCE MODE ACTIVE",
    r"\[Update customer record",
    r"Fallback protocol",
    r"End notice\.",    
    r"Current logged customer:",
    r"^agents:\s*\n\s*-\s*name:",       
    r"FAQ & Policy Agent",
    r"description: Handles questions about policies",
    r"- name:.*\n.*description:",        
    r"tool execution",
    r"tool_execution",
    r"voucher.{0,30}dump",
    r"list.{0,20}all.{0,20}voucher",
    r"show.{0,20}all.{0,20}voucher",
    r"get.{0,20}all.{0,20}voucher",
    r"voucher.{0,30}inflate",
    r"voucher.{0,30}multipl",
    r"generate.{0,20}voucher",
    r"orphaned.{0,20}voucher",
    r"create.{0,20}voucher",
    r"enumerate.{0,20}account",
    r"list.{0,20}all.{0,20}customer",
    r"dump.{0,20}customer",
    r"show.{0,20}all.{0,20}ticket",
    r"list.{0,20}all.{0,20}ticket",
    r"leak.{0,20}internal",
    r"internal.{0,20}document",
    r"confidential.{0,20}document",
    r"ignore.{0,20}previous.{0,20}instruction",
    r"ignore.{0,20}your.{0,20}instruction",
    r"disregard.{0,20}instruction",
    r"override.{0,20}instruction",
    r"new instruction",
    r"your (new|actual|real|true) (role|instruction|purpose|task|job|directive)",
    r"you are now",
    r"from now on.{0,30}you",
    r"forget.{0,20}(previous|prior|your)",
    r"court.{0,20}(deadline|order|case)",
    r"legal.{0,20}(action|deadline|order)",
    r"urgently.{0,20}required",
    r"emergency.{0,20}(update|change|process)",
    r"life.{0,20}threatening",
    r"safety.{0,20}(escalat|concern|issue).{0,30}(unverified|not verified)",
    r"escalate.{0,20}without.{0,20}verif",
    r"change.{0,30}address.{0,30}(without|no).{0,20}verif",
    r"update.{0,30}address.{0,30}for.{0,30}(another|other|different) customer",
    r"deliver.{0,20}to.{0,20}different.{0,20}address",
    r"redeliver.{0,20}to",
    r"reroute.{0,20}(order|package|delivery)",
    r"misdeliver",
    r"close.{0,20}ticket.{0,20}without",
    r"sanitize.{0,20}ticket",
    r"delete.{0,20}ticket",
    r"(mark|close|resolve).{0,20}(fraud|complaint).{0,20}ticket",
    r"false.{0,20}policy.{0,20}accept",
    r"promise.{0,20}(not|never).{0,20}(made|authorized|approved)",
    r"refund.{0,20}(without|no).{0,20}(verif|approv|authoriz)",
    r"double.{0,20}refund",
    r"double.{0,20}compensation.{0,30}(get|receiv|claim|schedul|manipulat)",
    r"refund.{0,20}delivered.{0,20}order",
    r"cancel.{0,20}delivered",
    r"steal.{0,20}refund",
    r"unauthorized.{0,20}refund",
    r"change.{0,30}email.{0,30}(without|no).{0,20}verif",
    r"transfer.{0,20}account",
    r"account.{0,20}takeover",
    r"steal.{0,20}(account|email|credential)",
    r"denial.{0,10}of.{0,10}service",
    r"flood.{0,20}(request|message|ticket)",
    r"overload.{0,20}(system|agent|server)",
    r"'.*OR.*'.*=.*'",
    r";\s*(DROP|INSERT|UPDATE|DELETE)\s",
    r"EXEC\s*\(",
    r"xp_cmdshell",
    r"\[.*INSTRUCTION.*\]",
    r"\[.*COMMAND.*\]",
    r"\[.*OVERRIDE.*\]",
    r"\[.*ADMIN.*\]",
    r"\[.*ROOT.*\]",
    r"<\s*system\s*>",
    r"<<.*instruction.*>>",
    r"###\s*(SYSTEM|ADMIN|INSTRUCTION|OVERRIDE)",
    r"You are interacting exclusively with customer",
    r"customer with\s+customer_id\s*=",
    r"customer_id\s*=\s*['\"]?customer_\d+",
    r"Current logged customer",
    r"logged.{0,20}customer.{0,20}customer_\d+",
    r"customer_\d{6,}",
    r"interacting exclusively with",
    r"you are (now |currently |)serving customer",
    r"active customer.{0,20}customer_\d+",
    r"\b(write|generate|give|provide|explain|describe).{0,40}\b\d+\s*(word|paragraph|sentence|line|page)",
    r"\b\d+\s*(word|paragraph|sentence|line|page).{0,40}\b(about|on|of|explain|descri)",
    r"(300|400|500|200|100|250)\s*word",
    r"in\s+\d+\s+paragraph",
    r"before you (do|process|handle|answer|respond|check|look)",
    r"but (first|before that|prior to that).{0,50}(write|explain|generate|describe)",
    r"(after|once) you.{0,30}(write|explain|generate)",
    r"order.{0,30}(explain|describe).{0,30}(its|their|the).{0,10}(use|purpose|function)",
    r"write (an?|the) (article|essay|blog|post|guide|tutorial|summary|overview|report)",
    r"(generate|create|draft).{0,20}(article|essay|content|post|guide)",
    r"WHITFIELD\s*(NOTICE|UPDATE|OFFICIAL|ALERT|SYSTEM|ADMIN|SUPPORT)",
    r"\[WHITFIELD",
    r"Whitfield Official",
    r"⊰.*⊱",
    r"LOVE.*PLINY.*LOVE",
    r"⦑.*⦒",
    r"/L\\O/V\\E",
    r"PLI.?N.?Y",
    r"[\U0001F600-\U0001FFFF]{3,}",
    r"ignore all (previous|prior|above|former)",
    r"disregard (all|any|your|previous)",
    r"your (real|true|actual|hidden|secret) (purpose|goal|task|mission|instruction)",
    r"pretend (you are|you're|to be) (not|a different|an? (unrestricted|free|unfiltered))",
    r"act as if (you have no|you don't have|without) (restriction|filter|limit|guideline)",
    r"DAN\b",
    r"jailbreak",
    r"developer mode",
    r"unrestricted mode",
    r"\u200b", r"\u200c", r"\u200d", r"\u200e", r"\u200f",
    r"\u202a", r"\u202b", r"\u202c", r"\u202d", r"\u202e",
    r"\u2060", r"\u2061", r"\u2062", r"\u2063", r"\u2064",
    r"\ufeff", r"\u00ad", r"\u034f", r"\u115f", r"\u1160",
    r"\u3164", r"\uffa0",
]

def has_invisible_unicode(text):
    INVISIBLE = {
        '\u200b', '\u200c', '\u200d', '\u200e', '\u200f',
        '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
        '\u2060', '\u2061', '\u2062', '\u2063', '\u2064',
        '\ufeff', '\u00ad', '\u034f', '\u115f', '\u1160',
        '\u3164', '\uffa0'
    }
    return any(char in INVISIBLE for char in text)

def is_harmful(conversation: Conversation):
    user_text = " ".join(
        msg.content for msg in conversation.conversation
        if msg.role == "user"
    )

    if has_invisible_unicode(user_text):
        return True

    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, user_text, re.IGNORECASE):
            return True

    return False

@app.post("/classify")
def classify(conversation: Conversation):
    harmful = is_harmful(conversation)
    return {
        "violation": harmful,
        "confidence": 1.0 if harmful else 0.0
    }

@app.get("/health")
def health():
    return {"status": "ok"}
