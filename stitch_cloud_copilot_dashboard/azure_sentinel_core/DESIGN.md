---
name: Azure Sentinel Core
colors:
  surface: '#f8f9ff'
  surface-dim: '#cbdbf5'
  surface-bright: '#f8f9ff'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#eff4ff'
  surface-container: '#e5eeff'
  surface-container-high: '#dce9ff'
  surface-container-highest: '#d3e4fe'
  on-surface: '#0b1c30'
  on-surface-variant: '#444653'
  inverse-surface: '#213145'
  inverse-on-surface: '#eaf1ff'
  outline: '#757684'
  outline-variant: '#c4c5d5'
  surface-tint: '#3755c3'
  primary: '#00288e'
  on-primary: '#ffffff'
  primary-container: '#1e40af'
  on-primary-container: '#a8b8ff'
  inverse-primary: '#b8c4ff'
  secondary: '#565e74'
  on-secondary: '#ffffff'
  secondary-container: '#dae2fd'
  on-secondary-container: '#5c647a'
  tertiary: '#003272'
  on-tertiary: '#ffffff'
  tertiary-container: '#00489e'
  on-tertiary-container: '#9cbbff'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#dde1ff'
  primary-fixed-dim: '#b8c4ff'
  on-primary-fixed: '#001453'
  on-primary-fixed-variant: '#173bab'
  secondary-fixed: '#dae2fd'
  secondary-fixed-dim: '#bec6e0'
  on-secondary-fixed: '#131b2e'
  on-secondary-fixed-variant: '#3f465c'
  tertiary-fixed: '#d8e2ff'
  tertiary-fixed-dim: '#adc6ff'
  on-tertiary-fixed: '#001a42'
  on-tertiary-fixed-variant: '#004395'
  background: '#f8f9ff'
  on-background: '#0b1c30'
  surface-variant: '#d3e4fe'
typography:
  headline-lg:
    fontFamily: Inter
    fontSize: 30px
    fontWeight: '700'
    lineHeight: 38px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: Inter
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  label-md:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.05em
  headline-lg-mobile:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '700'
    lineHeight: 32px
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  container-max: 1440px
  gutter: 1.5rem
  sidebar-width: 260px
  stack-sm: 0.5rem
  stack-md: 1rem
  stack-lg: 2rem
---

## Brand & Style

The design system is engineered for high-stakes decision-making in cloud infrastructure. It targets DevOps engineers, CISOs, and FinOps analysts who require immediate clarity amidst complex data. The personality is **Professional, Analytical, and Vigilant**.

The aesthetic follows a **Corporate / Modern** approach with a hybrid interface: a high-contrast dark sidebar for navigational focus and a clean, high-clarity light content area for data density. The emotional response should be one of "controlled oversight"—where the user feels in total command of their cloud spend and security posture. This is achieved through systematic alignment, a restricted color palette, and a hierarchy that prioritizes critical alerts without inducing fatigue.

## Colors

The palette is anchored by **Navy Blue (#1E40AF)**, symbolizing stability and corporate trust. 

- **Primary Navigation:** Uses the Dark Mode profile (Secondary #0F172A) to create a "command center" frame.
- **Content Area:** Uses a Light Mode profile with subtle grey-blue backgrounds (#F8FAFC) to reduce glare during long sessions.
- **Functional Logic:** 
    - **Critical (Red):** Used for scores < 50 and active security breaches.
    - **Warning (Orange):** Used for scores 50-80 and cost overruns.
    - **Success (Green):** Used for scores > 80 and optimized resources.
- **Grays:** A neutral Slate scale is used for borders and secondary text to maintain a crisp, professional appearance.

## Typography

The design system utilizes **Inter** as the primary typeface for its exceptional legibility in data-heavy environments. Its neutral, systematic tone ensures the UI disappears so the data can speak. 

**JetBrains Mono** is introduced as a secondary label font for resource IDs, IP addresses, and cost metrics, providing a technical texture that fits the Cloud Copilot persona. 

Maintain tight tracking (-1% to -2%) on larger headlines to ensure a compact, authoritative look. All body text should use a standard weight (400), reserving semi-bold (600) for UI actions and headers to maintain a clear information hierarchy.

## Layout & Spacing

This design system uses a **fixed-fluid hybrid grid**. The sidebar remains fixed at 260px, while the main content area utilizes a 12-column fluid grid with a maximum cap of 1440px to prevent excessive line lengths on ultra-wide monitors.

- **Desktop:** 12 columns, 24px (1.5rem) gutters, 32px external margins.
- **Tablet:** 8 columns, 16px gutters, 24px margins.
- **Mobile:** 4 columns, 16px gutters, 16px margins. Sidebar collapses into a bottom-nav or hamburger overlay.

Spacing follows an 8px base unit. Generous whitespace (stack-lg) is required between disparate data widgets to prevent cognitive overload, while internal card components use tighter spacing (stack-sm) to show relationship.

## Elevation & Depth

To maintain a clean and professional look, the design system avoids heavy shadows. Instead, it utilizes **Tonal Layers** and **Subtle Ambient Shadows**.

- **Level 0 (Background):** #F8FAFC (Slate 50).
- **Level 1 (Cards/Surface):** White (#FFFFFF) with a 1px border in Slate 200.
- **Level 2 (Hover/Active):** A very soft shadow: `0 4px 6px -1px rgb(0 0 0 / 0.05), 0 2px 4px -2px rgb(0 0 0 / 0.05)`.

The dark sidebar uses depth through color saturation rather than shadow, staying flat to the "back" of the UI, while active content "pops" forward using white surfaces.

## Shapes

The shape language is **Soft (0.25rem)**. This provides a modern feel without the playfulness of highly rounded "bubble" designs.

- **Primary Buttons & Inputs:** 4px (0.25rem) corner radius.
- **Dashboard Cards:** 8px (0.5rem) corner radius for a distinct container feel.
- **Status Badges/Chips:** Full pill-shaped (999px) to differentiate them from interactive buttons.

Consistency in corner radius across all form inputs is critical to maintaining a "technical tool" aesthetic.

## Components

- **Buttons:** Primary buttons use the Navy Blue (#1E40AF) with white text. Secondary buttons use a Slate 200 border and no fill.
- **Cards:** White background, 1px Slate 200 border. Headers within cards should have a subtle bottom divider (#F1F5F9).
- **Status Gauges:** Use a "Donut Chart" style for Security/Cost scores. The stroke color must dynamically change based on the score threshold (Red/Orange/Green).
- **Input Fields:** Use a 1px border (#CBD5E1). On focus, the border shifts to Primary Blue with a subtle 2px blue glow (ring).
- **Data Tables:** Row-based with alternating "zebra" stripes is discouraged. Use thin 1px horizontal dividers and high row height (56px) for readability.
- **Copilot Sidebar:** A secondary, right-aligned slide-out panel for the AI assistant. Use a very subtle Blue-50 background tint to differentiate it from the main data area.
- **Chips:** Small, uppercase monospaced text for tags (e.g., `AWS`, `PRODUCTION`, `CRITICAL`).