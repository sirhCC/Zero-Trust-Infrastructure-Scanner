// Type definitions for simple-statistics
declare module 'simple-statistics' {
  export function linearRegression(data: number[][]): {
    m: number;
    b: number;
  };
  
  export function mean(data: number[]): number;
  export function median(data: number[]): number;
  export function standardDeviation(data: number[]): number;
  export function variance(data: number[]): number;
  export function zScore(value: number, mean: number, standardDeviation: number): number;
  export function quantile(data: number[], p: number): number;
  export function interquartileRange(data: number[]): number;
}
