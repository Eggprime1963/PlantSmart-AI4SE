| Function            | Test Case ID   | Scenario Description                | Input / Mock Setup                       | Expected Output / Behavior        | Category       |
|:--------------------|:---------------|:------------------------------------|:-----------------------------------------|:----------------------------------|:---------------|
| createTransporter() | CT_01          | All email env vars set correctly    | EMAIL_USER, PASS, HOST, PORT, SECURE set | Returns valid transporter         | Happy path     |
| createTransporter() | CT_02          | Missing EMAIL_USER                  | EMAIL_USER undefined                     | Logs warning, returns transporter | Edge case      |
| createTransporter() | CT_03          | Missing EMAIL_PASS                  | EMAIL_PASS undefined                     | Logs warning, returns transporter | Edge case      |
| createTransporter() | CT_04          | EMAIL_USE_SERVICE = true            | EMAIL_USE_SERVICE='true'                 | Uses service-based config         | Happy path     |
| createTransporter() | CT_05          | Invalid port (465 but secure=false) | EMAIL_PORT=465, EMAIL_SECURE=false       | Logs warning or sets secure=true  | Boundary       |
| createTransporter() | CT_06          | No env vars set                     | None                                     | Falls back to defaults            | Error recovery |
| createTransporter() | CT_07          | Transporter creation fails          | nodemailer.createTransport throws        | Throws/logs creation error        | Error scenario |
| generateToken(user) | GT_01          | Valid user full name                | user with givenName, familyName          | Returns valid JWT                 | Happy path     |
| generateToken(user) | GT_02          | Missing familyName                  | givenName only                           | full_name=givenName               | Edge case      |
| generateToken(user) | GT_03          | Missing givenName                   | familyName only                          | full_name=familyName              | Edge case      |
| generateToken(user) | GT_04          | Missing JWT_SECRET                  | JWT_SECRET undefined                     | Throws error                      | Error scenario |
| generateToken(user) | GT_05          | Empty user                          | {}                                       | Throws or malformed token         | Error scenario |
| forgotPassword()    | FP_01          | Valid email, existing user          | email in DB                              | 200 success message               | Happy path     |
| forgotPassword()    | FP_02          | Missing email in body               | {}                                       | 400 Email required                | Error          |
| forgotPassword()    | FP_03          | Invalid email format                | email='abc@'                             | 400 invalid format                | Edge           |
| forgotPassword()    | FP_04          | Nonexistent user                    | findByEmail null                         | 404 user not found                | Error          |
| forgotPassword()    | FP_05          | Token generation error              | createPasswordResetToken throws          | 500 error                         | Error          |
| forgotPassword()    | FP_06          | Email service unavailable           | verifyConnection() false                 | 500 Email failed                  | Error          |
| forgotPassword()    | FP_07          | Email sending ECONNECTION           | sendEmail throws ECONNECTION             | 500 with logs                     | Error          |
| forgotPassword()    | FP_08          | Email sending EAUT                  | sendEmail throws EAUT                    | 500 auth error                    | Error          |
| forgotPassword()    | FP_09          | SystemLog fails silently            | SystemLog.info throws                    | Still 200 success                 | Edge           |
| forgotPassword()    | FP_10          | Check reset link correctness        | email HTML contains token                | Valid reset URL                   | Integration    |
| resetPassword()     | RP_01          | Valid token and password            | token valid, match passwords             | 200 success                       | Happy          |
| resetPassword()     | RP_02          | Missing token                       | query.token undefined                    | 400 error                         | Error          |
| resetPassword()     | RP_03          | Missing password fields             | missing password                         | 400 error                         | Error          |
| resetPassword()     | RP_04          | Password mismatch                   | password != confirmPassword              | 400 mismatch                      | Error          |
| resetPassword()     | RP_05          | Short password (<6)                 | password='123'                           | 400 too short                     | Edge           |
| resetPassword()     | RP_06          | Invalid token                       | jwt.verify throws                        | 401 invalid token                 | Error          |
| resetPassword()     | RP_07          | User not found                      | findByResetToken null                    | 401 invalid token                 | Error          |
| resetPassword()     | RP_08          | Password update fails               | updatePassword throws                    | 500 error                         | Error          |
| resetPassword()     | RP_09          | Confirmation email fails            | sendMail throws                          | Logs error but 200                | Edge           |
| resetPassword()     | RP_10          | HTML name check                     | user.family_name provided                | Name matches                      | Integration    |
| changePassword()    | CP_01          | Valid current and new password      | All fields valid                         | 200 success                       | Happy          |
| changePassword()    | CP_02          | Missing one field                   | missing confirmPassword                  | 400 required fields               | Error          |
| changePassword()    | CP_03          | New password mismatch               | newPassword != confirmPassword           | 400 mismatch                      | Error          |
| changePassword()    | CP_04          | User not found                      | findById null                            | 404 not found                     | Error          |
| changePassword()    | CP_05          | Invalid current password            | bcrypt.compare false                     | 401 incorrect                     | Error          |
| changePassword()    | CP_06          | Weak new password                   | newPassword='12345'                      | 400 weak                          | Edge           |
| changePassword()    | CP_07          | Update password fails               | updatePassword throws                    | 500 error                         | Error          |
| changePassword()    | CP_08          | Integration check                   | password hashed check                    | Hash verified                     | Integration    |
| register()          | RG_01          | Valid registration                  | Unique email                             | 201 success + token               | Happy          |
| register()          | RG_02          | Duplicate email                     | findByEmail returns existing             | 409 duplicate                     | Error          |
| register()          | RG_03          | DB lookup error                     | findByEmail throws                       | Continues to creation             | Edge           |
| register()          | RG_04          | Save duplicate                      | save() throws 23505                      | 409 duplicate                     | Error          |
| register()          | RG_05          | Other save error                    | save() throws generic                    | 500 error                         | Error          |
| register()          | RG_06          | Welcome email fails                 | sendWelcomeEmail throws                  | Logs only                         | Edge           |
| register()          | RG_07          | Missing email or password           | invalid body                             | 400 missing field                 | Error          |
| register()          | RG_08          | Token gen fails                     | generateToken throws                     | 500 fail                          | Error          |
| sendWelcomeEmail()  | SW_01          | Valid email sending                 | user.email valid                         | Success                           | Happy          |
| sendWelcomeEmail()  | SW_02          | Invalid user email                  | user.email invalid                       | Logs error                        | Error          |
| sendWelcomeEmail()  | SW_03          | Missing EMAIL_USER                  | EMAIL_USER undefined                     | Warning logged                    | Edge           |
| sendWelcomeEmail()  | SW_04          | nodemailer.sendMail throws          | simulate ECONNECTION                     | Logs error                        | Error          |
| sendWelcomeEmail()  | SW_05          | Email greeting correctness          | user.family_name provided                | Correct greeting                  | Integration    |
| login()             | LG_01          | Valid credentials                   | correct email/password                   | 200 success + token               | Happy          |
| login()             | LG_02          | Missing email                       | body missing email                       | 400 error                         | Error          |
| login()             | LG_03          | User not found                      | findByEmail null                         | 401 invalid                       | Error          |
| login()             | LG_04          | Incorrect password                  | validatePassword false                   | 401 invalid                       | Error          |
| login()             | LG_05          | DB access error                     | findByEmail throws                       | 500 error                         | Error          |
| login()             | LG_06          | Token generation fails              | generateToken throws                     | 500 error                         | Error          |
| login()             | LG_07          | Integration user fields check       | givenName, familyName, role              | All fields returned               | Integration    |
| logout()            | LO_01          | Valid user logs out                 | req.user present                         | 200 success                       | Happy          |
| logout()            | LO_02          | No user in request                  | req.user undefined                       | 200 success logs Unknown          | Edge           |
| logout()            | LO_03          | Log writing fails                   | SystemLog.write throws                   | Still 200                         | Edge           |