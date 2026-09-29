/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        // ── Ivory Security Lab 시맨틱 토큰 ──────────────────────────────
        canvas: "#F8F9FB",   // 앱 전체 배경
        surface: "#FFFFFF",  // 카드 / 패널 / 사이드바
        hairline: "#E5E7EB", // 테두리
        ink: "#111827",      // 본문 텍스트 (Primary)
        muted: "#6B7280",    // 보조 텍스트 (Secondary)
        info: "#64748B",     // 정보/중립

        // Primary (Enterprise Blue)
        primary: {
          DEFAULT: "#1E3A8A",
          hover: "#1D4ED8",
          50:  "#EEF3FF",
          100: "#DCE6FF",
          200: "#BBCEFE",
          300: "#8FB0FC",
          400: "#5B87F5",
          500: "#1D4ED8",  // 밝은 강조 / hover
          600: "#1E40AF",
          700: "#1E3A8A",  // 기본 Primary
          800: "#1B3478",
          900: "#172554",
        },

        // Accent (Amber)
        accent: { DEFAULT: "#F59E0B", soft: "#FEF3C7" },

        // 상태 색상
        success: "#22C55E",
        warning: "#F59E0B",
        danger:  "#EF4444",

        // 취약점 Severity
        severity: {
          critical: "#DC2626",
          high:     "#F97316",
          medium:   "#EAB308",
          low:      "#22C55E",
          info:     "#64748B",
        },

        // ── 브랜드 블루 램프(brand-*) — 진한 네이비 강조에 사용 ───────────────
        // (레거시 토큰을 중립명 brand-* 로 개명, 색상 값은 동일 유지)
        brand: {
          50:  "#EEF3FF",
          100: "#DCE6FF",
          200: "#BBCEFE",
          300: "#8FB0FC",
          400: "#5B87F5",
          500: "#1E3A8A",  // primary
          600: "#1D4ED8",  // hover
          700: "#1E40AF",
          800: "#1B3478",
          900: "#172554",
        },
        navy: {
          700: "#1E3A8A",
          800: "#172554",
          900: "#0F172A",
          950: "#0F172A",
        },
      },
      fontFamily: {
        sans: ["Pretendard", "Noto Sans KR", "system-ui", "sans-serif"],
      },
      boxShadow: {
        card: "0 1px 3px rgba(16,24,40,0.06), 0 1px 2px rgba(16,24,40,0.04)",
        "card-hover": "0 4px 16px rgba(16,24,40,0.08)",
        primary: "0 2px 8px rgba(30,58,138,0.18)",
      },
    },
  },
  plugins: [],
};
