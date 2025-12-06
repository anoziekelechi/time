// src/context/AuthContext.tsx — FINAL LAW (NOW USING AXIOS)
import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from "react";
import api from "@/api/client"; // YOUR SACRED CLIENT

export interface User {
  id: number;
  email: string;
  surname: string;
  othernames: string;
  phone?: string;
  verified: boolean;
  disabled: boolean;
  date_added: string;
}

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  login: (csrfToken?: string) => void; // optional now
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const fetchUser = useCallback(async () => {
    try {
      setIsLoading(true);
      const response = await api.get<User>("/api/auth/me");
      setUser(response.data);
    } catch (error: any) {
      // 401/403 → interceptor handles refresh → if fails, we get here
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  const login = (csrfToken?: string) => {
    if (csrfToken) {
      localStorage.setItem("csrf_token", csrfToken);
    }
    fetchUser(); // This will now use fresh cookies + CSRF
  };

  const logout = async () => {
    try {
      await api.post("/api/auth/logout");
    } catch (error) {
      // Even if logout fails, we still clear frontend
      console.warn("Logout API failed, clearing anyway");
    } finally {
      localStorage.removeItem("csrf_token");
      setUser(null);
      window.location.href = "/login";
    }
  };

  return (
    <AuthContext.Provider value={{ user, isLoading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within AuthProvider");
  return context;
}





// new
// src/api/client.ts — FINAL, SACRED, NIGERIAN BANK LAW
import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "",
  withCredentials: true,
});

let isRefreshing = false;
let failedQueue: any[] = [];

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("csrf_token");
  if (token) config.headers["X-CSRF-Token"] = token;
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry && !originalRequest.url.includes("/refresh")) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then(() => api(originalRequest)).catch(err => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        await fetch("/api/auth/refresh", { method: "POST", credentials: "include" });
        failedQueue.forEach(p => p.resolve());
        failedQueue = [];
        return api(originalRequest);
      } catch {
        failedQueue.forEach(p => p.reject());
        failedQueue = [];
        localStorage.removeItem("csrf_token");
        window.location.href = "/login";
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export default api;



// src/pages/Profile.tsx — FINAL, CLEAN, USES CONTEXT
import { useAuth } from "@/context/AuthContext";
import { Navigate } from "react-router-dom";

export default function Profile() {
  const { user, isLoading, logout } = useAuth();

  if (isLoading) return <div className="p-8 text-center">Loading...</div>;
  if (!user) return <Navigate to="/login" replace />;

  return (
    <div className="max-w-2xl mx-auto p-8 bg-white rounded-lg shadow">
      <h1 className="text-3xl font-bold mb-6">
        Welcome, {user.surname} {user.othernames}
      </h1>
      
      <div className="space-y-4 text-lg">
        <p><strong>Email:</strong> {user.email}</p>
        <p><strong>Phone:</strong> {user.phone || "Not set"}</p>
        <p><strong>Member since:</strong> {new Date(user.date_added).toLocaleDateString("en-GB")}</p>
        <p><strong>Status:</strong> {user.verified ? "Verified" : "Unverified"}</p>
      </div>

      <button onClick={logout} className="mt-8 bg-red-600 hover:bg-red-700 text-white px-6 py-3 rounded">
        Logout
      </button>
    </div>
  );
}
