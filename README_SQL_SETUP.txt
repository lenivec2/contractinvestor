FundLedger - Full Vercel + Supabase package

FILES
- index.html: current FundLedger web app
- FundLedger_Supabase_Setup.sql: database tables, RLS policies, Admin Dashboard RPCs, account restriction RPCs, and Contact Us RPCs

SUPABASE SETUP
1. Open Supabase for your FundLedger project.
2. Go to SQL Editor.
3. Open/copy FundLedger_Supabase_Setup.sql and run the entire file.
4. Make the intended master-admin Auth user an admin by running the optional UPDATE at the bottom of the SQL file, replacing the email.
5. Have that admin user sign out and sign back in.
6. In the app, open the Admin area and create/unlock the four-digit Admin PIN.

IMPORTANT
- The app uses the Supabase publishable key in index.html. Do not put a Supabase service_role/secret key in the browser.
- Existing contract_tracker_data rows are preserved by the SQL setup.
- Existing contact_messages rows are preserved by the SQL setup.
- Referral Fee in Add Contract must be entered; use 0 when there is no referral fee.
- Estimated Profit = Gross Return - Admin Fee - Participant Funded Amount - Referral Fee.
- Profit % = Estimated Profit / (Participant Funded Amount + Referral Fee) * 100.
