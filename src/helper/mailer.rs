// pub mod emailer {
//     use crate::middleware::error::UserCustomResponseError;
//     use lettre::smtp::{authentication::Credentials, response::Response};
//     use lettre::{SmtpClient, Transport};
//     use lettre_email::EmailBuilder;
//     use std::str;

//     pub async fn send_email_for_password_reset(
//         user_name: &str,
//         reset_link: &str,
//         to: &str,
//     ) -> Result<Response, UserCustomResponseError> {
//         match SmtpClient::new_simple("smtp.gmail.com") {
//             Ok(smtp) => {
//                 let mut mailer = smtp
//                     .credentials(Credentials::new(
//                         "logeddata@gmail.com".into(),
//                         "logdatatxt".into(),
//                     ))
//                     .transport();

//                 let email= match EmailBuilder::new()
//      .to(to)
//      .from("logeddata@gmail.com")
//      .subject("Astro Build Password Reset")
//      .html(format!("

//                     <head>
//     <link rel='preconnect' href='https://fonts.googleapis.com'>
//     <link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>
//     <link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;700&display=swap' rel='stylesheet'>
// </head>

// <body style='margin: 0;
// padding: 0;
// box-sizing: border-box;
// font-family: Inter, sans-serif;'>
//     <div class='container' style='display: grid;
// grid-template-columns: 1fr;
// row-gap: 1rem;
// align-items: center;
// justify-content: center;
// width: 65%;
// margin: 50px auto;
// padding: 50px;
// border: 2px solid black;
// border-radius: 10px;'>
//         <h1>Hi, {}</h1>
//         <p> we've received a request to reset your password. if you didn't make the request,just ignore this email.
//      Otherwise ,you can reset your password using this link:</p>
//         <div style='display: grid;
//     grid-template-columns: 1fr;
//     row-gap: 0.25rem;'>
           
//      <div>
//          <a href={} >Click here to reset your Password </a>  
//      </div>
//             </pre>
//             <p>Astrobuild &copy Astrolab Agency</p>
//         </div>
// </body>
         
//      ",user_name,reset_link)).build(){
//          Ok(builder)=>Ok(builder),
//          Err(_email_error)=>Err(UserCustomResponseError::InternalError)
//         };
//                 match mailer.send(email?.into()) {
//                     Ok(mail) => Ok(mail),
//                     Err(_smtp_error) => Err(UserCustomResponseError::InternalError),
//                 }
//             }
//             Err(_smtp_error) => Err(UserCustomResponseError::InternalError),
//         }
//     }

//     pub async fn send_user_login_account(
//         user_name: &str,
//         password: &str,
//         role: &str,
//         to: &str,
//     ) -> Result<Response, UserCustomResponseError> {
//         match SmtpClient::new_simple("smtp.gmail.com") {
//             Ok(smtp) => {
//                 let mut mailer = smtp
//                     .credentials(Credentials::new(
//                         "logeddata@gmail.com".into(),
//                         "logdatatxt".into(),
//                     ))
//                     .transport();

//                 let email = match EmailBuilder::new()
//                     .to(to)
//                     .from("logeddata@gmail.com")
//                     .subject("Astro Build Create Account")
//                     .html(format!(
//                         "
                        
//                     <head>
//     <link rel='preconnect' href='https://fonts.googleapis.com'>
//     <link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>
//     <link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;700&display=swap' rel='stylesheet'>
// </head>

// <body style='margin: 0;
// padding: 0;
// box-sizing: border-box;
// font-family: Inter, sans-serif;'>
//     <div class='container' style='display: grid;
// grid-template-columns: 1fr;
// row-gap: 1rem;
// align-items: center;
// justify-content: center;
// width: 65%;
// margin: 50px auto;
// padding: 50px;
// border: 2px solid black;
// border-radius: 10px;'>
//         <h1>Hi, {}</h1>
//         <p>You've received a request to create a new account </p>
//         <div style='display: grid;
//     grid-template-columns: 1fr;
//     row-gap: 0.25rem;'>
//             <h2>Email: {}</h2>
//             <h2>Password: {}</h2>
//             </pre>
//             <p>Astrobuild &copy Astrolab Agency</p>
//         </div>
// </body>
//      ",
//                         user_name, to, password
//                     ))
//                     .build()
//                 {
//                     Ok(builder) => Ok(builder),
//                     Err(_email_error) => Err(UserCustomResponseError::InternalError),
//                 };
//                 match mailer.send(email?.into()) {
//                     Ok(mail) => Ok(mail),
//                     Err(_smtp_error) => Err(UserCustomResponseError::InternalError),
//                 }
//             }
//             Err(_smtp_error) => Err(UserCustomResponseError::InternalError),
//         }
//     }
// }
