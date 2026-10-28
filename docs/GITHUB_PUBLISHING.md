# Publish BenCore Shield on GitHub

Suggested repository name: **BenCore-Shield**  
Suggested description: **BenCore Shield is a Windows 11 security inspection dashboard for Microsoft Defender scans, processes, services, startup tasks, and threat history. Developed by Benie Mansueto Vison.**

1. Open https://github.com/new and choose the desired repository owner.
2. Enter repository name `BenCore-Shield`, add the description, and select Public or Private. **Do not enable a starter README, template, license or .gitignore**, since the project already includes its own README and `.gitignore`.
3. Select **Create repository**.
4. On the empty repository page, choose **uploading an existing file** (or **Add file → Upload files**).
5. Extract the BenCore Shield package and upload **its contents**, keeping the `docs`, `.github/workflows`, `tools`, and top-level scripts in their original paths. **Do not upload only the ZIP**.
6. Commit with `Initial preview: BenCore Shield v1.0`.
7. Open the repository page and make sure `README.md` displays and `.github/workflows/check.yml` is visible.
8. Before any public release, **test all UI actions on a Windows 11 VM**, carefully review any errors, and consider digitally signing PowerShell scripts.

For a real dashboard screenshot after testing, make a GitHub folder `images` and upload `bencore-shield-dashboard.png`. Add `![BenCore Shield dashboard](images/bencore-shield-dashboard.png)` in the README.

No GitHub release binary, compiled executable or Windows installer is included in this source package.
