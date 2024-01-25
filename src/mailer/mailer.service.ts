import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerService {

    private async transporter() {
        // const testAccount = await nodemailer.createTestAccount();
        // console.log(testAccount); 
        
        // const transport = nodemailer.createTransport({
        //     host: 'localhost',
        //     port: 1025,
        //     ignoreTLS: true,
        //     auth: {
        //         user: testAccount.user,
        //         pass: testAccount.pass,
        //     },
        // });
        const transporter = nodemailer.createTransport({
            host: 'smtp.ethereal.email',
            port: 587,
            auth: {
                user: 'caesar79@ethereal.email',
                pass: 'NZ5Q4J1nfvWxBtt1dH'
            }
        });
        return transporter;
    }

    async sendSignupConfirmation(email: string) {
        (await this.transporter()).sendMail({
            from: 'app@localhost.com',
            to: email,
            subject: 'Account created',
            html: '<h3>Your account has been created successfully</h3>'
        });
    }

    async sendResetPassword(email: string, url: string, code: string) {
        (await this.transporter()).sendMail({
            from: 'app@localhost.com',
            to: email,
            subject: 'Reset your password',
            html: `
                <h3>Click <a href="${url}">here</a> to reset your password</h3>
                <p>Copy this code: ${code}</p>
            `
        });
    }
}
