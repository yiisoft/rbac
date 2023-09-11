<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

/**
 * Items are RBAC hierarchy entities that could be assigned to the user.
 * Both roles and permissions are items.
 */
abstract class Item
{
    public const TYPE_ROLE = 'role';
    public const TYPE_PERMISSION = 'permission';

    /**
     * @var string The item description.
     */
    private string $description = '';

    /**
     * @var string|null Name of the rule associated with this item.
     */
    private ?string $ruleName = null;

    /**
     * @param string $name The name of the item. This must be globally unique.
     */
    final public function __construct(private string $name)
    {
    }

    /**
     * @return string Type of the item.
     */
    abstract public function getType(): string;

    /**
     * @return string Authorization item name.
     */
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

    /**
     * @return static
     */
    final public function withRuleName(?string $ruleName): self
    {
        $new = clone $this;
        $new->ruleName = $ruleName;
        return $new;
    }

    final public function getRuleName(): ?string
    {
        return $this->ruleName;
    }

    /**
     * @return array Authorization item attribute values indexed by attribute names.
     *
     * @psalm-return array{
     *     name:string,
     *     description:string,
     *     ruleName:string|null,
     *     type:string,
     * }
     */
    final public function getAttributes(): array
    {
        return [
            'name' => $this->getName(),
            'description' => $this->getDescription(),
            'ruleName' => $this->getRuleName(),
            'type' => $this->getType(),
        ];
    }
}
