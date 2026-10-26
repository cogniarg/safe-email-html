/**
 * Synthetic transactional email modeled on the markup real providers send:
 * an XHTML 1.0 Transitional document with <style> resets and media queries,
 * Outlook conditional comments, a hidden preheader, nested table layout, a
 * bulletproof button, and a styled <body>. It exercises the full-document
 * unwrapping path and the inline-style allowlist against realistic markup.
 */
export const transactionalEmailHtml = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en">
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>New sign in to your account</title>
    <style type="text/css">
      body { margin: 0; padding: 0; -webkit-text-size-adjust: 100%; }
      table { border-collapse: collapse; mso-table-lspace: 0pt; }
      .preheader { display: none !important; }
      @media all and (max-width: 639px) {
        .container { width: 100% !important; max-width: 600px !important; }
        .mobile-hidden { max-height: 0; display: none !important; }
      }
      .card { border: 1px solid #eeeef0; border-radius: 10px; }
    </style>
    <!--[if mso]>
      <style type="text/css">body, table, td, a { font-family: Arial, sans-serif !important; }</style>
    <![endif]-->
  </head>
  <body style="background-color: #f4f4f7; margin: 0px; padding: 0px" bgcolor="#f4f4f7">
    <div class="preheader" style="display: none; max-height: 0px; max-width: 0px; opacity: 0; overflow: hidden; visibility: hidden">
      A new device just signed in to your Example Accounts account.
    </div>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f4f4f7">
      <tr>
        <td align="center" valign="top" style="padding: 32px 16px">
          <table class="container" width="600" cellpadding="0" cellspacing="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 8px">
            <tr>
              <td align="left" valign="top" style="padding: 32px 32px 48px; font-family: Helvetica, Arial, sans-serif; color: #111827">
                <h1 style="font-size: 22px; line-height: 28px; margin: 0 0 16px">New sign in to your account</h1>
                <p style="font-size: 14px; line-height: 20px; margin: 0 0 24px">
                  A new device just signed in to your Example Accounts account.
                  If you don't recognize this device, review your account activity.
                </p>
                <table class="card" width="100%" cellpadding="0" cellspacing="0" border="0">
                  <tr>
                    <td style="color: #9ca3af; font-size: 14px; padding: 6px 16px 6px 20px">Device</td>
                    <td style="color: #111827; font-size: 14px; font-weight: 600; padding: 6px 20px 6px 0">Chrome on Linux</td>
                  </tr>
                  <tr>
                    <td style="color: #9ca3af; font-size: 14px; padding: 6px 16px 6px 20px">Location</td>
                    <td style="color: #111827; font-size: 14px; font-weight: 600; padding: 6px 20px 6px 0">Springfield</td>
                  </tr>
                </table>
                <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin-top: 24px">
                  <tr>
                    <td align="center" bgcolor="#111827" style="border-radius: 6px">
                      <a href="https://accounts.example.com/sessions/revoke?ticket=redacted" style="display: inline-block; padding: 12px 20px; color: #ffffff; font-size: 14px; font-weight: 600; text-decoration: none; border-radius: 6px">Sign out of this device</a>
                    </td>
                  </tr>
                </table>
                <p class="mobile-hidden" style="font-size: 12px; color: #9ca3af; margin: 32px 0 0">
                  &copy; 2026 Example Accounts &middot;
                  <a href="https://accounts.example.com/help" style="color: #9ca3af">Help</a>
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
`
