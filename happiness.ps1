# happiness.ps1 — a little dose of cheer. Run anytime you need it.

$colors = @('Yellow','Cyan','Green','Magenta','Red','Blue','White')

$affirmations = @(
    "You are doing better than you think.",
    "Someone is grateful you exist today.",
    "The world is more interesting because you're in it.",
    "Small progress is still progress.",
    "You've survived 100% of your worst days so far.",
    "Your future self is rooting for you.",
    "It's okay to rest. Productivity is not your worth.",
    "Something good is on its way.",
    "You are allowed to take up space.",
    "You handled today. That counts."
)

$facts = @(
    "Otters hold hands while sleeping so they don't drift apart.",
    "Honeybees can recognize human faces.",
    "Cows have best friends and get stressed when separated.",
    "Wombats poop cubes.",
    "A group of flamingos is called a 'flamboyance'.",
    "Sea otters keep a favorite rock in a pouch under their arm.",
    "Norway once knighted a penguin (Sir Nils Olav).",
    "Bumblebees can fly higher than Mount Everest.",
    "Goats have rectangular pupils so they can see almost 360 degrees.",
    "Pigeons can recognize themselves in mirrors."
)

$sun = @"
       \    |    /
        \   |   /
     ----- (*) -----
        /   |   \
       /    |    \
"@

Clear-Host
Write-Host ""
Write-Host $sun -ForegroundColor Yellow
Write-Host ""

$affirm = Get-Random -InputObject $affirmations
$fact   = Get-Random -InputObject $facts
$c1     = Get-Random -InputObject $colors
$c2     = Get-Random -InputObject $colors

Write-Host "  $affirm" -ForegroundColor $c1
Write-Host ""
Write-Host "  Did you know? $fact" -ForegroundColor $c2
Write-Host ""

# Cheerful little C-major arpeggio. Skip if Beep isn't supported (non-Windows).
try {
    foreach ($n in 523, 659, 784, 1047) { [Console]::Beep($n, 150) }
} catch { }
