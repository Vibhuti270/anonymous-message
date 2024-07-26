import {Awaitable, NextAuthOptions, RequestInternal, User} from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import dbConnect from "@/lib/dbConnect";
import UserModel from "@/model/User";
import dotenv from "dotenv";
dotenv.config();
export const authOptions: NextAuthOptions = {
    providers:[
        CredentialsProvider({
            id: "credentials",
            name: "Credentials",
            credentials: {
                username: { label: "Email", type: "text", placeholder: "" },
                password: { label: "Password", type: "password" }
            },
            async authorize(credentials:any): Promise<any>{
                await dbConnect();
                try {
                    const user = await UserModel.findOne({
                        $or:[
                            {email:credentials.identifiers},
                            {username:credentials.identifiers}
                        ]
                    })

                    if(!user){
                        throw new Error('No user found with this email')
                    }

                    if(!user.isVerified){
                        throw new Error("please verify your account first")
                    }

                    const isPasswordCorrect = await bcrypt.compare(credentials.password,user.password);

                    if(isPasswordCorrect){
                        return user;
                    } else{
                        throw new Error("Incorrect password");
                    }
                } catch (err:any) {
                    throw new Error(err);
                }
            }
        })
    ],
    callbacks:{
        async jwt({token,user}){
            return token
        },
        async session({session,token}){
            return session
        }
    },
    pages:{
        signIn: '/signin',
        
    },
    session:{
        strategy: "jwt"
    },
    secret: process.env.NEXTAUTH_SECRET
}