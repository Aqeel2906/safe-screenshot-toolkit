"""Text normalisation for the Message Checker.

Scammers dodge keyword filters with tricks like "0TP", "p@ssw0rd",
full-width letters or invisible zero-width characters. Rules are matched
against a cleaned-up copy of the text, and an index map points every
character of that copy back to the original so findings can still be
highlighted in place.
"""
import re
import unicodedata

# Invisible characters often inserted to break up keywords.
INVISIBLE = re.compile("[­͏؜᠎​-‏‪-‮⁠-⁤﻿]")

# Look-alike substitutions, one character in and one out, so the index map still applies.
LEET = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a", "$": "s", "!": "i", "|": "l",
})


def normalise(original: str) -> tuple[str, list[int]]:
    """Return (text, index_map).

    text      -- lower-cased, de-obfuscated copy used for matching
    index_map -- index_map[i] is the position in `original` that text[i] came from
    """
    chars: list[str] = []
    index_map: list[int] = []
    for i, ch in enumerate(original):
        if INVISIBLE.match(ch):
            continue  # dropped, so not mapped
        # NFKC folds full-width and stylised letters ("ＯＴＰ", "𝐎𝐓𝐏") to plain ASCII.
        for c in unicodedata.normalize("NFKC", ch).lower():
            chars.append(c)
            index_map.append(i)
    return "".join(chars), index_map


def de_leet(text: str) -> str:
    """Leetspeak-decoded copy. Same length as the input, so the same index map applies."""
    return text.translate(LEET)


def spaced(word: str) -> str:
    """Regex that tolerates separators between letters: "otp" also matches "o t p", "o.t.p"."""
    return r"[\s.\-_*]?".join(re.escape(c) for c in word)
