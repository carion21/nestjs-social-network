import { ConflictException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { SignupDto } from './dto/signupDto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import * as speakeasy from 'speakeasy';
import { MailerService } from 'src/mailer/mailer.service';
import { SigninDto } from './dto/signinDto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ResetPasswordDto } from './dto/resetpasswordDto';
import { ResetPasswordConfirmationDto } from './dto/resetPasswordConfirmationDto';
import { DeleteAccountDto } from './dto/deleteAccountDto';

@Injectable()
export class AuthService {
    constructor(
        private readonly prismaService: PrismaService,
        private readonly mailerService: MailerService,
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService
    ) {}
    
    async signup(signupDto: SignupDto) {
        const { email, username, password} = signupDto;

        // Verifier si l'utilisateur existe déjà
        const user = await this.prismaService.user.findUnique({
            where: {
                email: email,
            },
        });
        if (user) throw new ConflictException('User already exists');
        // Hasher le mot de passe
        const hash = await bcrypt.hash(password, 10);
        // Créer un nouvel utilisateur
        const new_user = await this.prismaService.user.create({
            data: {
                username: username,
                email: email,
                password: hash,
            },
        });
        // Envoyer un email de confirmation
        this.mailerService.sendSignupConfirmation(email);
        // Retourner une réponse de succès
        return {
            message: 'User created successfully',
            data: new_user
        };
    }

    async signin(signinDto: SigninDto) {
        const { email, password } = signinDto;

        // Vérifier si l'utilisateur existe
        const user = await this.prismaService.user.findUnique({
            where: {
                email: email,
            },
        });
        if (!user) throw new NotFoundException('User not found');
        // Vérifier si le mot de passe est correct
        const match = await bcrypt.compare(password, user.password);
        if (!match) throw new UnauthorizedException('Wrong password');
        // Retourner une réponse de succes avec un jwt token
        const payload = {
            sub: user.id,
            username: user.username,
            email: user.email
        }
        const token = this.jwtService.sign(
            payload,
            {
                secret: this.configService.get('JWT_SECRET'),
                expiresIn: '1h',
            }
        );
        return {
            message: 'User logged in successfully',
            data: {
                user: user,
                token: token
            }
        };
    }

    async resetPassword(resetPasswordDto: ResetPasswordDto) {
        const { email } = resetPasswordDto;
        // Vérifier si l'utilisateur existe
        const user = await this.prismaService.user.findUnique({
            where: {
                email: email,
            },
        });
        if (!user) throw new NotFoundException('User not found');
        // generer un code de réinitialisation
        const code = speakeasy.totp({
            secret: this.configService.get('OTP_SECRET'),
            digits: 5,
            step: 900,
            encoding: 'base32'
        });
        // Envoyer un email de réinitialisation
        const url = "http://localhost:8000/auth/reset-password-confrmation";
        this.mailerService.sendResetPassword(email, url, code);
        // Retourner une réponse de succès
        return {
            message: 'Reset password email sent successfully'
        };
    }

    async resetPasswordConfirmation(resetPasswordConfirmationDto: ResetPasswordConfirmationDto) {
        const { email, password, code } = resetPasswordConfirmationDto;
        // Vérifier si l'utilisateur existe
        const user = await this.prismaService.user.findUnique({
            where: {
                email: email,
            },
        });
        if (!user) throw new NotFoundException('User not found');
        // Vérifier si le code est correct
        const match = speakeasy.totp.verify({
            secret: this.configService.get('OTP_SECRET'),
            digits: 5,
            encoding: 'base32',
            token: code,
            step: 900
        });
        if (!match) throw new UnauthorizedException('Wrong code');
        // Hasher le nouveau mot de passe
        const hash = await bcrypt.hash(password, 10);
        // Mettre à jour le mot de passe de l'utilisateur
        const updated_user = await this.prismaService.user.update({
            where: {email},
            data: {
                password: hash
            }
        });
        // Retourner une réponse de succès
        return {
            message: 'Password reset successfully'
        };
    }

    async deleteAccount(userId: number, deleteAccountDto: DeleteAccountDto) {
        const { password } = deleteAccountDto;
        // Vérifier si l'utilisateur existe
        const user = await this.prismaService.user.findUnique({
            where: {
                id: userId
            }
        })
        if (!user) throw new NotFoundException('User not found');
        // Vérifier si le mot de passe est correct
        const match = bcrypt.compare(password, user.password);
        if (!match) throw new UnauthorizedException('Password does not match');
        // Supprimer l'utilisateur
        await this.prismaService.user.delete({
            where: {
                id: userId
            }
        })
        // Retourner une réponse de succès
        return {
            message: 'User deleted successfully'
        };
    }
}
