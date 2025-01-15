import { Column, Model, Table } from 'sequelize-typescript';

@Table({ tableName: 'users' })
export class User extends Model {
  @Column({
    allowNull: false,
    unique: false,
  })
  name: string;

  @Column({
    allowNull: false,
    unique: true,
  })
  email: string;

  @Column({
    allowNull: false,
    unique: true,
  })
  mobileNumber: string;

  @Column({
    allowNull: false,
  })
  password: string;
}
