import {resend} from "@/lib/resend"
import VerificationEmail from "../../emails/VerificationEmail"

import { ApiResponse } from "@/types/ApiResponse";

export async function sendVerificationEmail (
    email: string,
    username: string,
    verifyCode: string
): Promise<ApiResponse>{
    try {
        await resend.emails.send({
            from: 'anonymous@resend.dev',
            to: email,
            subject: 'Verification Email',
            react: VerificationEmail({username,otp:verifyCode}),
          });
        return {
            success: true, message:'Verification email sent successfully'
        }
    } catch (emailError) {
        console.log("error sending verification email", emailError);
        return {
            success: false, message:'Failed to send verification email'
        }
    }
}