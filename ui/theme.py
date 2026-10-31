"""
Theme configuration for CustomTkinter cybersecurity interface.
Defines deep navy & charcoal palette, electric cyan/blue accents, status colors, and typography.
"""

class CyberTheme:
    # Deep Navy & Charcoal Backgrounds
    BG_MAIN = "#0A0E17"
    BG_SIDEBAR = "#080C14"
    BG_CARD = "#111827"
    BG_CARD_HOVER = "#162032"
    BG_INPUT = "#090D16"
    BG_DIFF = "#060A11"

    # Borders & Dividers
    BORDER = "#1E293B"
    BORDER_ACCENT = "#3B82F6"
    BORDER_CYAN = "#00F0FF"

    # Electric Neon & Status Accents
    ACCENT_CYAN = "#00F0FF"
    ACCENT_EMERALD = "#10B981"
    ACCENT_AMBER = "#F59E0B"
    ACCENT_CRIMSON = "#EF4444"
    ACCENT_PURPLE = "#A855F7"
    ACCENT_BLUE = "#3B82F6"

    # Status Badges
    STATUS_CLEAN = "#10B981"
    STATUS_MODIFIED = "#EF4444"
    STATUS_MISSING = "#F59E0B"
    STATUS_ERROR = "#EF4444"

    # Risk Levels
    RISK_HIGH = "#EF4444"
    RISK_MEDIUM = "#F59E0B"
    RISK_LOW = "#10B981"
    RISK_CLEAN = "#3B82F6"

    # Text Colors
    TEXT_PRIMARY = "#F1F5F9"
    TEXT_SECONDARY = "#94A3B8"
    TEXT_MUTED = "#64748B"
    TEXT_DIFF_ADD = "#4ADE80"
    TEXT_DIFF_DEL = "#F87171"
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
        if st == "CLEAN" or st == "UNCHANGED":
            return cls.STATUS_CLEAN
        elif st == "MODIFIED":
            return cls.STATUS_MODIFIED
        elif st == "MISSING":
            return cls.STATUS_MISSING
        return cls.STATUS_ERROR
