import { AuthorUserDto } from './author-user.dto';
import { AuthorAdminDto } from './author-admin.dto';

export interface NewsWithAuthor {
  id: number;
  title: string;
  text: string;
  url: string;
  status: boolean;
  createdAt: Date;
  updatedAt: Date;
  authorId: number;
  author: AuthorUserDto | AuthorAdminDto;
}
