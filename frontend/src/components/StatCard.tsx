import { ReactNode } from 'react';
import { cn } from '@/lib/utils';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: ReactNode;
  trend?: string;
  variant?: 'default' | 'danger' | 'warning' | 'success';
}

const variantStyles = {
  default: 'border-border',
  danger: 'border-destructive/30 glow-danger',
  warning: 'border-warning/30',
  success: 'border-success/30',
};

const iconVariant = {
  default: 'text-primary',
  danger: 'text-destructive',
  warning: 'text-warning',
  success: 'text-success',
};

export default function StatCard({ title, value, icon, trend, variant = 'default' }: StatCardProps) {
  return (
    <div className={cn(
      'bg-card/80 backdrop-blur-sm border rounded-lg p-5 transition-all hover:bg-card',
      variantStyles[variant]
    )}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider">{title}</p>
          <p className="text-2xl font-bold font-mono mt-2 text-foreground">{value}</p>
          {trend && (
            <p className={cn(
              'text-xs font-mono mt-1',
              trend.startsWith('+') ? 'text-destructive' : 'text-success'
            )}>
              {trend}
            </p>
          )}
        </div>
        <div className={cn('p-2 rounded-md bg-muted/50', iconVariant[variant])}>
          {icon}
        </div>
      </div>
    </div>
  );
}
