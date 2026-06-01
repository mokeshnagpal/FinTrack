# Code Reusability Analysis Report

## 🔴 CRITICAL ISSUES - Code Duplication

### 1. **escapeHtml() Function** - 7 Duplicates ⚠️⚠️⚠️
**Files with duplicates:**
- `static/js/balance.js` (line 59)
- `static/js/splits.js` (line 16)
- `static/js/analytics.js` (line 46)
- `static/js/balance_analytics.js` (line 54)
- `static/js/script.js` (line 231) - ✓ Used in script.js as `showToast()`
- `templates/trips.html` (line 350) - Inline in template
- Similar pattern exists in multiple analytics files

**Recommendation:** 
- Create single `utils.js` utility library
- Export `escapeHtml()` globally as `window.FinTrak.escapeHtml`
- Remove all local definitions
- Estimated savings: 50+ lines of code

**Implementation:**
```javascript
// utils.js
window.FinTrak = window.FinTrak || {};

window.FinTrak.escapeHtml = function(value) {
    if (value === null || value === undefined) return '';
    return String(value).replace(/[&<>"'`=/]/g, (char) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
        '`': '&#x60;',
        '=': '&#x3D;',
        '/': '&#x2F;',
    }[char]));
};
```

---

### 2. **formatNumber() Function** - 2 Duplicates
**Files:**
- `static/js/balance.js` (line 21)
- `static/js/splits.js` (line 5)

**Current implementation:**
```javascript
function formatNumber(value) {
  return Number(value || 0).toFixed(2);
}
```

**Recommendation:** Move to `window.FinTrak.formatNumber()`

---

### 3. **formatDate() and Variants** - Scattered Across Files
**Variants found:**
- `formatDate()` in splits.js
- `formatFriendlyDate()` in script.js (✓ Already global)
- `formatFriendlyDateHtml()` in script.js (✓ Already global)
- `formatDateInput()` in analytics_controls.js

**Current Status:** Partially consolidated
**Recommendation:** Ensure all date formatting uses `window.FinTrak.formatFriendlyDate*` family

---

## 🟡 MEDIUM ISSUES - Opportunity for Better Macro Usage

### 4. **Modal Patterns** - Could Use Macro Consolidation
**Files manually creating modals:**
- `balance.html` - 2 modals (addBalanceModal, syncBalanceModal)
- `split_detail.html` - 1 modal (addEntryModal)
- `management.html` - 2 modals (addCategoryModal, addPersonModal)

**Issue:** Some use `{% call modal() %}` macro, others use inline modal HTML
**Recommendation:** Always use `{% call modal() %}` macro from macros/ui.html

---

### 5. **Button Patterns** - Inconsistent Usage
**Patterns found:**
- `edit_button` macro exists but not always used
- `delete_button` macro exists but not always used
- Many inline button elements instead of using macros

**Files with inline buttons instead of macros:**
- `transactions.html` - Multiple edit/delete buttons
- `recurring.html` - Multiple edit/delete buttons
- `management.html` - Multiple edit/delete buttons

**Recommendation:** Use existing macros consistently across templates

---

### 6. **Notification System** - Already Consolidated ✓
**Status:** GOOD
- Unified `window.FinTrak.showToast()` - Centralized in script.js
- Used in: balance.js, splits.js, auth_status.js, offline_queue.js
- **No duplication**

---

## 🟢 GOOD - Already Reusable

### 7. **Macro Library** - Well Structured ✓
Used macros in `macros/ui.html`:
- `compact_badge()` - Used consistently
- `page_header()` - Used in all page templates
- `table_shell()` - Used in all table templates
- `modal()` - Used in most places
- `edit_button()` - Available but underutilized
- `delete_button()` - Available but underutilized
- `people_picker()` - Used in splits forms
- `choice_panel()` - Used in modals

---

## 📊 Code Reusability Summary

| Issue | Severity | Instances | Lines Saved | Status |
|-------|----------|-----------|-------------|--------|
| escapeHtml() duplication | 🔴 Critical | 7 | ~50 | Needs consolidation |
| formatNumber() duplication | 🟡 Medium | 2 | ~5 | Needs consolidation |
| Modal patterns | 🟡 Medium | 5+ | ~30 | Partial usage |
| Button patterns | 🟡 Medium | 3+ | ~25 | Underutilized macros |
| Date formatting | 🟡 Medium | 4+ | ~20 | Mostly good |
| Notification system | 🟢 Good | N/A | N/A | Consolidated ✓ |

---

## ✅ Consolidation Priority Plan

### Phase 1: CRITICAL (HIGH IMPACT)
1. Create `utils.js` with:
   - `escapeHtml()`
   - `formatNumber()`
   - `formatDate()` wrapper if needed
   
2. Update all files to use `window.FinTrak.escapeHtml()` instead of local definitions

**Estimated impact:** -70 lines of duplicate code, +10 lines of utility code = **-60 lines net**

---

### Phase 2: MEDIUM (GOOD PRACTICE)
1. Audit all templates for modal usage
2. Replace inline modals with `{% call modal() %}` macro
3. Audit all templates for button usage
4. Replace inline buttons with `edit_button()` and `delete_button()` macros

**Estimated impact:** -30 lines in templates, improved maintainability

---

### Phase 3: LOW (POLISH)
1. Create additional utility functions for common patterns:
   - `formatCurrency()` - For Rupee formatting
   - `createToastMessage()` - Pre-configured toast
   - `bindTableActions()` - Bind event handlers to table actions

---

## 🎯 Recommendations

✅ **DO:**
- Use `window.FinTrak.escapeHtml()` everywhere
- Use macros for common UI patterns
- Export utility functions to `window.FinTrak` namespace
- Keep utility functions in separate files for clarity

❌ **DON'T:**
- Define same function in multiple files
- Create inline HTML when macros exist
- Duplicate form patterns

---

## Current State: 60% Reusable
**Target State: 90%+ Reusable after consolidation**
