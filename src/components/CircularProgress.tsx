import React from 'react';

interface CircularProgressProps {
  score: number;
  maxScore?: number;
}

export function CircularProgress({ score, maxScore = 100 }: CircularProgressProps) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / maxScore) * circumference;

  return (
    <div className="relative w-32 h-32 flex items-center justify-center">
      {/* Background circle */}
      <svg className="absolute top-0 left-0 w-full h-full transform -rotate-90">
        <circle
          cx="64"
          cy="64"
          r={radius}
          stroke="currentColor"
          strokeWidth="8"
          fill="transparent"
          className="text-slate-800"
        />
        {/* Progress circle */}
        <circle
          cx="64"
          cy="64"
          r={radius}
          stroke="currentColor"
          strokeWidth="8"
          fill="transparent"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          className="text-emerald-500 transition-all duration-1000 ease-out"
          strokeLinecap="round"
        />
      </svg>
      
      <div className="text-center z-10">
        <div className="text-4xl font-semibold text-white tracking-tight">{score}</div>
        <div className="text-sm text-slate-400 font-medium mt-[-4px]">/ 100</div>
      </div>
    </div>
  );
}
