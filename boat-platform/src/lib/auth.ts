import { type NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import { prisma } from "./db";

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "E-Mail", type: "email" },
        password: { label: "Passwort", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) return null;

        const user = await prisma.user.findUnique({
          where: { email: credentials.email },
          include: { dealer: { select: { id: true, companyName: true } } },
        });

        if (!user || !user.isActive) return null;

        const valid = await bcrypt.compare(credentials.password, user.passwordHash);
        if (!valid) return null;

        return {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          dealerId: user.dealer?.id ?? null,
          companyName: user.dealer?.companyName ?? null,
        };
      },
    }),
  ],
  session: { strategy: "jwt", maxAge: 7 * 24 * 60 * 60 },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.role = (user as Record<string, unknown>).role;
        token.dealerId = (user as Record<string, unknown>).dealerId;
        token.companyName = (user as Record<string, unknown>).companyName;
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        const u = session.user as Record<string, unknown>;
        u.id = token.sub;
        u.role = token.role;
        u.dealerId = token.dealerId;
        u.companyName = token.companyName;
      }
      return session;
    },
  },
  pages: {
    signIn: "/dealer/login",
  },
};
