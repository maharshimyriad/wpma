<?php

declare(strict_types=1);

namespace Wpma\Engine;

final class TerminalActivityIndicator
{
    private const FRAMES = ['.  ', '.. ', '...'];

    /** @var callable(string): void */
    private $writer;
    private mixed $proc = null;
    private ?string $sentinelPath = null;
    private ?string $message = null;
    private bool $staticMode = false;

    /** @param callable(string): void $writer */
    public function __construct(
        private readonly bool $enabled,
        private readonly bool $interactive,
        callable $writer,
    ) {
        $this->writer = $writer;
    }

    public function start(string $message): void
    {
        $this->stop();

        if (!$this->enabled) {
            return;
        }

        $this->message = $message;

        if (!$this->interactive) {
            $this->staticMode = true;
            ($this->writer)(sprintf("     %s...\n", $message));
            return;
        }

        $sentinelPath = tempnam(sys_get_temp_dir(), 'wpma_act_');
        if ($sentinelPath === false) {
            $this->staticMode = true;
            ($this->writer)(sprintf("     %s...\n", $message));
            return;
        }

        $script = <<<'PHP'
$sentinel = $argv[1] ?? '';
$message = $argv[2] ?? '';
$frames = ['.  ', '.. ', '...'];
$index = 0;
while ($sentinel !== '' && file_exists($sentinel)) {
    fwrite(STDERR, "\r     {$message} " . $frames[$index % 3] . str_repeat(' ', 12));
    fflush(STDERR);
    usleep(250000);
    $index++;
}
PHP;

        $nullDevice = PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null';
        $spec = [
            0 => ['file', $nullDevice, 'r'],
            1 => ['file', 'php://stderr', 'w'],
            2 => ['file', 'php://stderr', 'w'],
        ];

        $proc = @proc_open(
            [PHP_BINARY, '-r', $script, $sentinelPath, $message],
            $spec,
            $pipes,
            null,
            null,
            ['bypass_shell' => true]
        );

        if (!is_resource($proc)) {
            @unlink($sentinelPath);
            $this->staticMode = true;
            ($this->writer)(sprintf("     %s...\n", $message));
            return;
        }

        $this->proc = $proc;
        $this->sentinelPath = $sentinelPath;
    }

    public function stop(?string $suffix = null): void
    {
        if ($this->staticMode) {
            if ($suffix !== null && $this->message !== null) {
                ($this->writer)(sprintf("     %s... %s\n", $this->message, $suffix));
            }
            $this->reset();
            return;
        }

        if (is_resource($this->proc)) {
            if ($this->sentinelPath !== null && file_exists($this->sentinelPath)) {
                @unlink($this->sentinelPath);
            }

            usleep(50000);
            @proc_terminate($this->proc);
            @proc_close($this->proc);
        }

        if ($this->interactive) {
            if ($suffix !== null && $this->message !== null) {
                ($this->writer)(sprintf("\r     %s... %s%s\n", $this->message, $suffix, str_repeat(' ', 20)));
            } else {
                ($this->writer)("\r" . str_repeat(' ', 120) . "\r");
            }
        }

        if ($this->sentinelPath !== null && file_exists($this->sentinelPath)) {
            @unlink($this->sentinelPath);
        }

        $this->reset();
    }

    public function __destruct()
    {
        $this->stop();
    }

    /** @return list<string> */
    public static function frames(): array
    {
        return self::FRAMES;
    }

    private function reset(): void
    {
        $this->proc = null;
        $this->sentinelPath = null;
        $this->message = null;
        $this->staticMode = false;
    }
}
