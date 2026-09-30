"""
Theme configuration for CustomTkinter cybersecurity interface.
Defines dark slate palette, neon accents, status colors, and typography.
"""

class CyberTheme:
    # Backgrounds
    BG_MAIN = "#0D1117"
    BG_SIDEBAR = "#090D13"
    BG_CARD = "#161B22"
    BG_CARD_HOVER = "#1C2128"
    BG_INPUT = "#0D1117"
    BG_DIFF = "#06090E"

    # Borders & Dividers
    BORDER = "#30363D"
    BORDER_ACCENT = "#388BFD"
    BORDER_CYAN = "#00F0FF"

    # Neon Accents
    ACCENT_CYAN = "#00F0FF"
    ACCENT_EMERALD = "#00E676"
    ACCENT_AMBER = "#FFB300"
    ACCENT_CRIMSON = "#FF5252"
    ACCENT_PURPLE = "#B388FF"
    ACCENT_BLUE = "#58A6FF"

    # Status Badges
    STATUS_CLEAN = "#00E676"
    STATUS_MODIFIED = "#FF5252"
    STATUS_MISSING = "#FFB300"
    STATUS_ERROR = "#FF5252"

    # Risk Levels
    RISK_HIGH = "#FF5252"
    RISK_MEDIUM = "#FFB300"
    RISK_LOW = "#00E676"
    RISK_CLEAN = "#58A6FF"

    # Text Colors
    TEXT_PRIMARY = "#F0F6FC"
    TEXT_SECONDARY = "#8B949E"
    TEXT_MUTED = "#6E7681"
    TEXT_DIFF_ADD = "#7EE787"
    TEXT_DIFF_DEL = "#FF7B72"
    TEXT_MONO = "#79C0FF"

    # Fonts
    FONT_FAMILY = "Segoe UI"
    FONT_MONO = "Consolas"

    @classmethod
    def get_risk_color(cls, risk_level: str) -> str:
        lvl = (risk_level or "").upper()
        if lvl == "HIGH":
            return cls.RISK_HIGH
        elif lvl == "MEDIUM":
            return cls.RISK_MEDIUM
        elif lvl == "LOW":
            return cls.RISK_LOW
        return cls.RISK_CLEAN

    @classmethod
    def get_status_color(cls, status: str) -> str:
        st = (status or "").upper()
        if st == "CLEAN":
            return cls.STATUS_CLEAN
        elif st == "MODIFIED":
            return cls.STATUS_MODIFIED
        elif st == "MISSING":
            return cls.STATUS_MISSING
        return cls.STATUS_ERROR
