import React from 'react';

import type { Coverage } from '../types';

interface CircularProgressProps {
  /** Null means there was not enough coverage to justify a number. */
  score: number | null;
  /** Drives the arc colour: a score over partial coverage is not a green light. */
  coverage?: Coverage;
  maxScore?: number;
}

export function CircularProgress({ score, coverage, maxScore = 100 }: CircularProgressProps) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;

  // With no score there is no arc to draw. A full grey ring would read as a
  // complete, healthy check; an empty one reads as what it is.
  const fraction = score === null ? 0 : score / maxScore;
  const strokeDashoffset = circumference - fraction * circumference;

  // A high score drawn in green reads as "you are fine". That is only an
  // honest thing to draw when the whole machine was actually inspected, so
  // partial coverage is shown in amber however good the number is.
  const arcColor =
    score === null
      ? 'text-slate-700'
      : score < 50
        ? 'text-rose-500'
        : coverage !== undefined && coverage !== 'complete'
          ? 'text-amber-500'
          : score >= 80
            ? 'text-emerald-500'
            : 'text-amber-500';

  const numberColor = coverage !== undefined && coverage !== 'complete' ? 'text-slate-200' : 'text-white';

  return (
    <div className="relative w-32 h-32 flex items-center justify-center shrink-0">
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
        {score !== null && (
          <circle
            cx="64"
            cy="64"
            r={radius}
            stroke="currentColor"
            strokeWidth="8"
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            className={`${arcColor} transition-all duration-1000 ease-out`}
            strokeLinecap="round"
          />
        )}
      </svg>

      <div className="text-center z-10">
        {score === null ? (
          <>
            <div className="text-4xl font-semibold text-slate-600 tracking-tight">--</div>
            <div className="text-xs text-slate-500 font-medium mt-0.5 px-2 leading-tight">
              Not enough data
            </div>
          </>
        ) : (
          <>
            <div className={`text-4xl font-semibold ${numberColor} tracking-tight`}>{score}</div>
            <div className="text-sm text-slate-400 font-medium mt-[-4px]">/ 100</div>
          </>
        )}
      </div>
    </div>
  );
}
