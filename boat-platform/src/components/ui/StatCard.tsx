interface StatCardProps {
  label: string;
  value: string | number;
  change?: string;
  icon?: React.ReactNode;
  color?: "blue" | "green" | "amber" | "red" | "purple";
}

const colorMap = {
  blue: "bg-sky-50 text-sky-600",
  green: "bg-emerald-50 text-emerald-600",
  amber: "bg-amber-50 text-amber-600",
  red: "bg-red-50 text-red-600",
  purple: "bg-purple-50 text-purple-600",
};

export default function StatCard({ label, value, change, icon, color = "blue" }: StatCardProps) {
  return (
    <div className="card p-6">
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-slate-500">{label}</p>
        {icon && (
          <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${colorMap[color]}`}>
            {icon}
          </div>
        )}
      </div>
      <p className="mt-2 text-3xl font-bold text-slate-900">{value}</p>
      {change && (
        <p className={`mt-1 text-sm font-medium ${change.startsWith("+") ? "text-emerald-600" : "text-red-500"}`}>
          {change}
        </p>
      )}
    </div>
  );
}
