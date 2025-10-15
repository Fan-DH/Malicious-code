$NUM_RUNS = 30
$yara_path = "C:\Users\Fan\Desktop\yara\yara64.exe"
$rule_file = "C:\Users\Fan\Desktop\malware\lab1\yara-rule2\t11.yar"
$sample_dir = "C:\Users\Fan\Desktop\malware\lab1\example"
$times = @()

for ($i = 1; $i -le $NUM_RUNS; $i++) {
    $elapsed = Measure-Command {
        & $yara_path -r $rule_file $sample_dir
    }
    
    $ms = $elapsed.TotalMilliseconds
    $times += $ms
    
    Write-Host "Cycle ${i}: $($ms.ToString('F2')) ms"
}

$total = ($times | Measure-Object -Sum).Sum
$average = ($times | Measure-Object -Average).Average

Write-Host "========================================"
Write-Host "Total Time: $($total.ToString('F2')) ms"
Write-Host "Average Time: $($average.ToString('F2')) ms"
