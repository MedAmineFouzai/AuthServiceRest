pub mod emailer {
    use crate::middleware::error::UserCustomResponseError;
    use lettre::smtp::{authentication::Credentials, response::Response};
    use lettre::{SmtpClient, Transport};
    use lettre_email::EmailBuilder;
    use std::str;

    pub async fn send_email_for_password_reset(
        user_name: &str,
        reset_link: &str,
        to: &str,
    ) -> Result<Response, UserCustomResponseError> {
        match SmtpClient::new_simple("smtp.gmail.com") {
            Ok(smtp) => {
                let mut mailer = smtp
                    .credentials(Credentials::new(
                        "logeddata@gmail.com".into(),
                        "logdatatxt".into(),
                    ))
                    .transport();

                let email= match EmailBuilder::new()
     .to(to)
     .from("logeddata@gmail.com")
     .subject("Astro Build Password Reset")
     .html(format!("

     <h3>Hi ,{}</h3>
     <p>
     we've received a request to reset your password. if you didn't make the request,just ignore this email.
     Otherwise ,you can reset your password using this link:
     </p>
     <div>
         <a href={}>Click here to reset your Password </a>  
     </div>
     <p>   
     Thanks.actix_web
     </p>
     <p>
     The AstroLab Team
     </p>  
     ",user_name,reset_link)).build(){
         Ok(builder)=>Ok(builder),
         Err(_email_error)=>Err(UserCustomResponseError::InternalError)
        };
                match mailer.send(email?.into()) {
                    Ok(mail) => Ok(mail),
                    Err(_smtp_error) => Err(UserCustomResponseError::InternalError),
                }
            }
            Err(_smtp_error) => Err(UserCustomResponseError::InternalError),
        }
    }
}
