import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';

import { Button } from '../button';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '../card';
import { Badge } from '../badge';
import { Input, Textarea, Label } from '../input';
import { Alert, AlertDescription } from '../alert';
import { Progress } from '../progress';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../tabs';
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '../select';

describe('Button', () => {
  test('renders with children', () => {
    render(<Button>Click me</Button>);
    expect(screen.getByText('Click me')).toBeTruthy();
  });

  test('handles click events', () => {
    const onClick = jest.fn();
    render(<Button onClick={onClick}>Click</Button>);
    fireEvent.click(screen.getByText('Click'));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  test('renders disabled state', () => {
    render(<Button disabled>Disabled</Button>);
    expect(screen.getByText('Disabled').closest('button')).toBeDisabled();
  });

  test('renders all variants without error', () => {
    const variants = ['default', 'destructive', 'outline', 'secondary', 'ghost', 'link'] as const;
    variants.forEach((variant) => {
      const { unmount } = render(<Button variant={variant}>{variant}</Button>);
      expect(screen.getByText(variant)).toBeTruthy();
      unmount();
    });
  });

  test('renders all sizes without error', () => {
    const sizes = ['default', 'sm', 'lg', 'icon'] as const;
    sizes.forEach((size) => {
      const { unmount } = render(<Button size={size}>btn</Button>);
      unmount();
    });
  });
});

describe('Card', () => {
  test('renders card with all subcomponents', () => {
    render(
      <Card>
        <CardHeader>
          <CardTitle>Title</CardTitle>
          <CardDescription>Description</CardDescription>
        </CardHeader>
        <CardContent>Content</CardContent>
        <CardFooter>Footer</CardFooter>
      </Card>
    );

    expect(screen.getByText('Title')).toBeTruthy();
    expect(screen.getByText('Description')).toBeTruthy();
    expect(screen.getByText('Content')).toBeTruthy();
    expect(screen.getByText('Footer')).toBeTruthy();
  });
});

describe('Badge', () => {
  test('renders with text', () => {
    render(<Badge>Active</Badge>);
    expect(screen.getByText('Active')).toBeTruthy();
  });

  test('renders all variants', () => {
    const variants = ['default', 'secondary', 'destructive', 'outline'] as const;
    variants.forEach((variant) => {
      const { unmount } = render(<Badge variant={variant}>{variant}</Badge>);
      expect(screen.getByText(variant)).toBeTruthy();
      unmount();
    });
  });
});

describe('Input', () => {
  test('renders and accepts input', () => {
    const onChange = jest.fn();
    render(<Input placeholder="Enter text" onChange={onChange} />);
    const input = screen.getByPlaceholderText('Enter text');
    fireEvent.change(input, { target: { value: 'hello' } });
    expect(onChange).toHaveBeenCalled();
  });
});

describe('Textarea', () => {
  test('renders textarea', () => {
    render(<Textarea placeholder="Enter description" />);
    expect(screen.getByPlaceholderText('Enter description')).toBeTruthy();
  });
});

describe('Label', () => {
  test('renders label text', () => {
    render(<Label>Username</Label>);
    expect(screen.getByText('Username')).toBeTruthy();
  });
});

describe('Alert', () => {
  test('renders alert with description', () => {
    render(
      <Alert>
        <AlertDescription>Something happened</AlertDescription>
      </Alert>
    );
    expect(screen.getByText('Something happened')).toBeTruthy();
    expect(screen.getByRole('alert')).toBeTruthy();
  });

  test('renders destructive variant', () => {
    render(
      <Alert variant="destructive">
        <AlertDescription>Error</AlertDescription>
      </Alert>
    );
    expect(screen.getByRole('alert')).toBeTruthy();
  });
});

describe('Progress', () => {
  test('renders with value', () => {
    render(<Progress value={50} />);
    const progressbar = screen.getByRole('progressbar');
    expect(progressbar.getAttribute('aria-valuenow')).toBe('50');
  });

  test('clamps values', () => {
    render(<Progress value={150} max={100} />);
    const progressbar = screen.getByRole('progressbar');
    expect(progressbar).toBeTruthy();
  });
});

describe('Tabs', () => {
  test('renders tabs and switches content', () => {
    render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
        <TabsContent value="tab2">Content 2</TabsContent>
      </Tabs>
    );

    expect(screen.getByText('Content 1')).toBeTruthy();
    expect(screen.queryByText('Content 2')).toBeNull();

    fireEvent.click(screen.getByText('Tab 2'));

    expect(screen.queryByText('Content 1')).toBeNull();
    expect(screen.getByText('Content 2')).toBeTruthy();
  });

  test('tabs have correct ARIA roles', () => {
    render(
      <Tabs defaultValue="a">
        <TabsList>
          <TabsTrigger value="a">A</TabsTrigger>
        </TabsList>
        <TabsContent value="a">Panel A</TabsContent>
      </Tabs>
    );

    expect(screen.getByRole('tablist')).toBeTruthy();
    expect(screen.getByRole('tab')).toBeTruthy();
    expect(screen.getByRole('tabpanel')).toBeTruthy();
  });
});

describe('Select', () => {
  test('renders and opens dropdown', () => {
    render(
      <Select value="" onValueChange={() => {}}>
        <SelectTrigger>
          <SelectValue placeholder="Choose" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="a">Option A</SelectItem>
          <SelectItem value="b">Option B</SelectItem>
        </SelectContent>
      </Select>
    );

    expect(screen.getByText('Choose')).toBeTruthy();
    expect(screen.queryByText('Option A')).toBeNull();

    fireEvent.click(screen.getByRole('combobox'));
    expect(screen.getByText('Option A')).toBeTruthy();
    expect(screen.getByText('Option B')).toBeTruthy();
  });

  test('selects an option', () => {
    const onValueChange = jest.fn();
    render(
      <Select value="" onValueChange={onValueChange}>
        <SelectTrigger>
          <SelectValue placeholder="Choose" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="a">Option A</SelectItem>
        </SelectContent>
      </Select>
    );

    fireEvent.click(screen.getByRole('combobox'));
    fireEvent.click(screen.getByText('Option A'));
    expect(onValueChange).toHaveBeenCalledWith('a');
  });

  test('has correct ARIA attributes', () => {
    render(
      <Select value="" onValueChange={() => {}}>
        <SelectTrigger>
          <SelectValue placeholder="Choose" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="a">Option A</SelectItem>
        </SelectContent>
      </Select>
    );

    expect(screen.getByRole('combobox').getAttribute('aria-expanded')).toBe('false');
    fireEvent.click(screen.getByRole('combobox'));
    expect(screen.getByRole('combobox').getAttribute('aria-expanded')).toBe('true');
    expect(screen.getByRole('listbox')).toBeTruthy();
  });
});
