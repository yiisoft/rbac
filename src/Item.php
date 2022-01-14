<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

/**
 * Items are RBAC hierarchy entities that could be assigned to the user.
 * Both roles and permissions are items.
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
     * @var string|null Name of the rule associated with this item.
     * @psalm-var class-string<RuleInterface>|null
     */
    private ?string $ruleName = null;

    /**
     * @var int|null UNIX timestamp representing the item creation time.
     */
    private ?int $createdAt = null;

    /**
     * @var int|null UNIX timestamp representing the item updating time.
     */
    private ?int $updatedAt = null;

    /**
     * @param string $name The name of the item. This must be globally unique.
     */
    final public function __construct(string $name)
    {
        $this->name = $name;
    }

    /**
     * @return string Type of the item.
     */
    abstract public function getType(): string;

    final public function getName(): string
    {
        return $this->name;
    }

    /**
     * @return static
     */
    final public function withName(string $name): self
    {
        $new = clone $this;
        $new->name = $name;
        return $new;
    }

    /**
     * @return static
     */
    final public function withDescription(string $description): self
    {
        $new = clone $this;
        $new->description = $description;
        return $new;
    }

    final public function getDescription(): string
    {
        return $this->description;
    }

    /** @psalm-param class-string<RuleInterface>|null $ruleName */
    final public function withRuleName(?string $ruleName): self
    {
        $new = clone $this;
        $new->ruleName = $ruleName;
        return $new;
    }

    /** @psalm-return class-string<RuleInterface>|null */
    final public function getRuleName(): ?string
    {
        return $this->ruleName;
    }

    /**
     * @return static
     */
    final public function withCreatedAt(int $createdAt): self
    {
        $new = clone $this;
        $new->createdAt = $createdAt;
        return $new;
    }

    final public function getCreatedAt(): ?int
    {
        return $this->createdAt;
    }

    /**
     * @return static
     */
    final public function withUpdatedAt(int $updatedAt): self
    {
        $new = clone $this;
        $new->updatedAt = $updatedAt;
        return $new;
    }

    final public function getUpdatedAt(): ?int
    {
        return $this->updatedAt;
    }

    final public function hasCreatedAt(): bool
    {
        return $this->createdAt !== null;
    }

    final public function hasUpdatedAt(): bool
    {
        return $this->updatedAt !== null;
    }

    /**
     * @psalm-return array{
     *     name:string,
     *     description:string,
     *     ruleName:class-string<RuleInterface>|null,
     *     type:string,
     *     updatedAt:int|null,
     *     createdAt:int|null,
     * }
     */
    final public function getAttributes(): array
    {
        return [
            'name' => $this->getName(),
            'description' => $this->getDescription(),
            'ruleName' => $this->getRuleName(),
            'type' => $this->getType(),
            'updatedAt' => $this->getUpdatedAt(),
            'createdAt' => $this->getCreatedAt(),
        ];
    }
}
