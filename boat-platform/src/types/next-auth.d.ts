import "next-auth";

declare module "next-auth" {
  interface Session {
    user: {
      id: string;
      name: string;
      email: string;
      role: "CUSTOMER" | "DEALER" | "ADMIN";
      dealerId: string | null;
      companyName: string | null;
    };
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    role: string;
    dealerId: string | null;
    companyName: string | null;
  }
}
