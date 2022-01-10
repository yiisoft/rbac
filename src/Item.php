<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

/**
 * For more details and usage information on Item, see the [guide article on security authorization](guide:security-authorization).
 */
abstract class Item implements ItemInterface
{
    public const TYPE_ROLE = 'role';
    public const TYPE_PERMISSION = 'permission';

    /**
     * @var string The name of the item. This must be globally unique.
     */
    private string $name;

    /**
     * @var string The item description.
     */
    private string $description = '';

    /**
     * @var string[] Names of the rules associated with this item.
     * @psalm-var array<class-string<Rule>>
     */
    private array $ruleNames = [];

    /**
     * @var int|null UNIX timestamp representing the item creation time.
     */
    private ?int $createdAt = null;

    /**
     * @var int|null UNIX timestamp representing the item updating time.
     */
    private ?int $updatedAt = null;

    public function __construct(string $name)
    {
        $this->name = $name;
    }

    abstract public function getType(): string;

    public function getName(): string
    {
        return $this->name;
    }

    public function withName(string $name): self
    {
        $new = clone $this;
        $new->name = $name;
        return $new;
    }

    public function withDescription(string $description): self
    {
        $new = clone $this;
        $new->description = $description;
        return $new;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function withRuleNames(array $ruleNames): self
    {
        // TODO: validate?
        $new = clone $this;
        $new->ruleNames = $ruleNames;
        return $new;
    }

    /** @psalm-return array<class-string<Rule>> */
    public function getRuleNames(): array
    {
        return $this->ruleNames;
    }

    public function withCreatedAt(int $createdAt): self
    {
        $new = clone $this;
        $new->createdAt = $createdAt;
        return $new;
    }

    public function getCreatedAt(): ?int
    {
        return $this->createdAt;
    }

    public function withUpdatedAt(int $updatedAt): self
    {
        $new = clone $this;
        $new->updatedAt = $updatedAt;
        return $new;
    }

    public function getUpdatedAt(): ?int
    {
        return $this->updatedAt;
    }

    public function hasCreatedAt(): bool
    {
        return $this->createdAt !== null;
    }

    public function hasUpdatedAt(): bool
    {
        return $this->updatedAt !== null;
    }

    public function getAttributes(): array
    {
        return [
            'name' => $this->getName(),
            'description' => $this->getDescription(),
            'ruleNames' => $this->getRuleNames(),
            'type' => $this->getType(),
            'updatedAt' => $this->getUpdatedAt(),
            'createdAt' => $this->getCreatedAt(),
        ];
    }
}
