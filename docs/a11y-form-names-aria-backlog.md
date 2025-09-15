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
Issues:
- Icon-only copy buttons (content_copy) rely on `title` but lack `aria-label`.
Actions:
- Add `aria-label="Copy Session ID"`, `aria-label="Copy User ID"` (and any other copy actions) to each button.
- (Optional) Add `Name` to read-only critical fields (`SessionId`, `UserId`).

### 6. TokenStatistics.razor
Issues:
- `RadzenNumeric` inputs `days` and `retainDays` lack `Name`.
- All icon buttons have Text (OK), but ensure any added pure icon buttons get `aria-label`.
Actions:
- Add `Name="DaysRange"`, `Name="RetainDays"`.

### 7. EditClientPages/RateLimiting.razor
Issues:
- Three `RadzenNumeric` controls missing `Name`.
Actions:
- Add `Name="RateLimitPerMinute"`, `RateLimitPerHour`, `RateLimitPerDay`.

### 8. EditClientPages/IdentityProviders.razor
Issues:
- Provider DropDown, search TextBox, display override TextBox, numeric order, text area claim mappings lack `Name`.
Actions:
- Add Names: `ProviderId`, `ProviderSearch`, `DisplayNameOverride`, `LinkOrder`, `LinkClaimMappings`.

### 9. Clients.razor
Issues:
- Search TextBox missing `Name`.
- Realm filter DropDown missing `Name`.
- Search button icon-only (Icon="search") missing `aria-label`.
Actions:
- Add `Name="ClientSearch"`, `Name="RealmFilter"`.
- Add `aria-label="Search clients"` to search button.

### 10. EditIdentityProviderDialog.razor
Issues:
- Many form inputs lack `Name` (DisplayName, Name, Type, IconUri, Order, OIDC/SAML fields, scopes, response type, etc.).
- Link management section: client DropDown, search, display override, order, claim mappings all missing `Name`.
Actions:
- Assign Names mirroring DTO property names (preferred).
- Add `Name` to OIDC toggles (UsePkce, GetClaimsFromUserInfo, etc.) and SAML switches.

### 11. IdentityProviderLinksDialog.razor
Issues:
- Client DropDown, search TextBox, display name override TextBox, order numeric, claim mapping text area missing `Name`.
Actions:
- Add Names: `ClientId`, `ClientSearch`, `DisplayNameOverride`, `Order`, `ClaimMappingsJson`.

### 12. Token / KPI Gradient Cards (various pages)
Note: Purely presentational; no changes required (no interactive input elements inside those cards).

### 13. General Pattern Validation
Add rule enforcement in future PRs:
- Every Radzen input: Must include a stable `Name` (aligned with model property).
- Every icon-only button (Icon set, Text omitted): Add `aria-label` describing action.

## Acceptance Criteria
For each file:
1. All interactive input components (`RadzenTextBox`, `RadzenNumeric`, `RadzenDropDown`, `RadzenTextArea`, `RadzenPassword`, `RadzenSwitch`, `RadzenCheckBox`, `RadzenDatePicker`) have a non-empty `Name` attribute following PascalCase or exact DTO property name where possible.
2. All icon-only `RadzenButton` components include a descriptive `aria-label` that would make sense to a screen reader user out of context.
3. No duplicate `Name` values within the same form scope.
4. Build succeeds (`dotnet build`) and no new analyzers/warnings are introduced related to unknown attributes.
5. Manual spot test: Inspect rendered HTML – inputs contain `name` attributes; buttons have `aria-label`.

## Implementation Plan
Order of execution (recommended):
1. High-traffic admin workflows: Users.razor, Clients.razor.
2. Dialogs & complex editors: EditIdentityResourceDialog, EditIdentityProviderDialog, IdentityProviderLinksDialog.
3. Configuration-heavy pages: EditRealmDefaults, EditUserPages/BasicInformation, SessionDetailsDialog.
4. Monitoring pages: TokenStatistics, RateLimiting, IdentityProviders (client edit section).
5. Remaining minor adjustments / consistency pass.

## Non-Goals
- Adding ARIA roles beyond button labels (Radzen already sets roles semantically).
- Refactoring layout or visual design.
- Adding full WCAG audits (focus only on names/aria-labels per current directive).

## Tracking
Create a PR per logical group (e.g., "a11y: add Name & aria-label to Users + Clients") to simplify review.

---
Generated initial assessment backlog. Update this file as tasks are completed.
