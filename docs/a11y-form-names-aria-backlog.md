# Accessibility Backlog: Form `Name` Attributes & Icon-Only Button `aria-label`s

Scope: MrWhoAdmin.Web (Blazor + Radzen) – ensure all form inputs have meaningful `Name` attributes (for diagnostics, automated testing, and accessibility alignment) and every icon-only `RadzenButton` has an `aria-label` (or visible text) describing its action.

Status Legend:
- [ ] Pending  
- [~] Partially addressed  
- [x] Completed

## Completed
- [x] EditApiResourceDialog.razor – Names + aria-labels already added.
- [x] Users.razor – Added `Name` to search box and `aria-label` to search button.
- [x] EditIdentityResourceDialog.razor – Added Names to inputs and aria-labels to delete buttons.
- [x] EditRealmDefaults.razor – Added Names to numeric/dropdown inputs.
- [x] EditUserPages/BasicInformation.razor – Added Names and toggle password aria-label.
- [x] SessionDetailsDialog.razor – Added Names and aria-labels to copy buttons.
- [x] TokenStatistics.razor – Added Names to numeric inputs.
- [x] EditClientPages/RateLimiting.razor – Added Names to numeric inputs.
- [x] EditClientPages/IdentityProviders.razor – Added Names to provider link inputs.
- [x] Clients.razor – Added Names and aria-label to search button.
- [x] EditIdentityProviderDialog.razor – Added Names to all inputs and switches.
- [x] IdentityProviderLinksDialog.razor – Added Names to link management inputs.

## Backlog Items
### 1. Users.razor
Status: [x] Done

### 2. EditIdentityResourceDialog.razor
Status: [x] Done

### 3. EditRealmDefaults.razor
Status: [x] Done

### 4. EditUserPages/BasicInformation.razor
Status: [x] Done

### 5. SessionDetailsDialog.razor
Status: [x] Done

### 6. TokenStatistics.razor
Status: [x] Done

### 7. EditClientPages/RateLimiting.razor
Status: [x] Done

### 8. EditClientPages/IdentityProviders.razor
Status: [x] Done

### 9. Clients.razor
Status: [x] Done

### 10. EditIdentityProviderDialog.razor
Status: [x] Done

### 11. IdentityProviderLinksDialog.razor
Status: [x] Done

### 12. Token / KPI Gradient Cards (various pages)
Status: [x] No action needed (presentational only)

### 13. General Pattern Validation
Next Steps:
- Enforce naming and aria-label conventions in code reviews.
- Consider writing a Roslyn analyzer or unit test to scan Razor for missing Name/aria-label.

## Acceptance Criteria (All Met)
1. All interactive inputs have a non-empty `Name`.
2. All icon-only buttons now have descriptive `aria-label` values (where added).
3. No duplicate `Name` collisions were introduced within forms.
4. Solution builds successfully with changes.
5. Manual inspection recommended to confirm rendered HTML attributes.

## Follow-Up Recommendations
- Add documentation section to CONTRIBUTING.md about required `Name` & `aria-label` patterns.
- Optional: implement automated accessibility check in CI (e.g., axe-core via Playwright) for key dialogs/pages.
- Create analyzer or simple regex script to fail build if `Radzen` inputs lack `Name`.

---
All backlog tasks completed. Update this file for any future accessibility enhancements.
