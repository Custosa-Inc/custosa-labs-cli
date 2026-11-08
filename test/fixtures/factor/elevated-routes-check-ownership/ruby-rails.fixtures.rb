# Made-up Rails controllers that lift the default scope.
class RecordsController < ApplicationController
  # ok: elevated-routes-check-ownership.ruby-rails.elevated-handler
  def show
    @record = Record.unscoped.find(params[:id])
    head :forbidden if @record.user_id != current_user.id
  end

  # ok: elevated-routes-check-ownership.ruby-rails.elevated-handler
  def archived
    @records = Record.unscoped.where(user: current_user, archived: true)
  end

  # ruleid: elevated-routes-check-ownership.ruby-rails.elevated-handler
  def restore
    Record.unscoped.find(params[:id]).update(deleted_at: nil)
  end

  # ruleid: elevated-routes-check-ownership.ruby-rails.elevated-handler
  def export
    skip_authorization
    send_data ActsAsTenant.without_tenant { Patient.all.to_csv }
  end

  # Scoped as usual: not an item.
  # ok: elevated-routes-check-ownership.ruby-rails.elevated-handler
  def index
    @records = Record.where(user: current_user)
  end
end

# None of these checks the record's owner.
# Case 1: audit record names the caller; the patient read lifts the default scope with no owner check
class PatientsController < ApplicationController
  # ruleid: elevated-routes-check-ownership.ruby-rails.elevated-handler
  def show
    AuditLog.create!(user: current_user, action: "show")
    render json: Patient.unscoped.find(params[:id])
  end
end
# Case 2: the caller's notifications scoped, the patient not
class PatientsController < ApplicationController
  # ruleid: elevated-routes-check-ownership.ruby-rails.elevated-handler
  def edit
    @count = current_user.notifications.where(read: false).count
    @patient = Patient.unscoped.find(params[:id])
  end
end
# Case 3: owner compared with a params value
class PatientsController < ApplicationController
  # ruleid: elevated-routes-check-ownership.ruby-rails.elevated-handler
  def update
    head :forbidden if params[:owner_id].to_i != current_user.id
    Patient.unscoped.find(params[:id]).update!(params.permit(:name))
  end
end
