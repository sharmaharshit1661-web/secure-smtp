import { useEffect, useRef, useState } from 'react';
import { getTierColor } from '../utils/colors';

export default function RiskGauge({ score = 0, tier = 'clean', size = 140 }) {
  const [animatedScore, setAnimatedScore] = useState(0);
  const rafRef = useRef(null);

  useEffect(() => {
    const start = performance.now();
    const duration = 800;
    const from = 0;
    const to = score;

    function animate(now) {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setAnimatedScore(from + (to - from) * eased);
      if (progress < 1) rafRef.current = requestAnimationFrame(animate);
    }

    rafRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(rafRef.current);
  }, [score]);

  const color = getTierColor(tier);
  const radius = (size - 20) / 2;
  const cx = size / 2;
  const cy = size / 2;
  const circumference = Math.PI * radius;
  const strokeDash = (animatedScore / 100) * circumference;

  const ticks = Array.from({ length: 21 }, (_, i) => {
    const angle = Math.PI + (i / 20) * Math.PI;
    const isMajor = i % 5 === 0;
    const innerR = radius - (isMajor ? 12 : 8);
    const outerR = radius - 2;
    return (
      <line
        key={i}
        x1={cx + innerR * Math.cos(angle)}
        y1={cy + innerR * Math.sin(angle)}
        x2={cx + outerR * Math.cos(angle)}
        y2={cy + outerR * Math.sin(angle)}
        stroke={isMajor ? 'rgba(255,255,255,0.2)' : 'rgba(255,255,255,0.08)'}
        strokeWidth={isMajor ? 1.5 : 0.8}
      />
    );
  });

  return (
    <svg width={size} height={size * 0.65} viewBox={`0 0 ${size} ${size * 0.65}`}>
      {ticks}
      {/* Background arc */}
      <path
        d={`M ${cx - radius} ${cy} A ${radius} ${radius} 0 0 1 ${cx + radius} ${cy}`}
        fill="none"
        stroke="rgba(255,255,255,0.06)"
        strokeWidth={6}
        strokeLinecap="round"
      />
      {/* Value arc */}
      <path
        d={`M ${cx - radius} ${cy} A ${radius} ${radius} 0 0 1 ${cx + radius} ${cy}`}
        fill="none"
        stroke={color}
        strokeWidth={6}
        strokeLinecap="round"
        strokeDasharray={`${strokeDash} ${circumference}`}
        style={{ filter: `drop-shadow(0 0 6px ${color})` }}
      />
      {/* Score text */}
      <text x={cx} y={cy - 8} textAnchor="middle" fill="var(--text-primary)"
        fontFamily="var(--font-mono)" fontSize={size * 0.19} fontWeight="700">
        {Math.round(animatedScore)}
      </text>
      <text x={cx} y={cy + 8} textAnchor="middle" fill="var(--text-muted)"
        fontFamily="var(--font-mono)" fontSize={size * 0.08}>
        / 100
      </text>
    </svg>
  );
}
